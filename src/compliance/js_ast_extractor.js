const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const filePath = process.argv[2];
if (!filePath) {
    console.error("No file path provided");
    process.exit(1);
}

try {
    const code = fs.readFileSync(filePath, 'utf-8');
    const ast = parser.parse(code, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript', 'classProperties', 'decorators-legacy'],
        errorRecovery: true
    });

    const extraction = {
        file: filePath,
        outbound_calls: [],
        api_endpoints: [],
        pii_fields: [],
        db_destinations: [],
        unused_pii_fields: [],
        third_party_transfers: [],
        unprotected_storage: []
    };

    const piiKeywords = ['email', 'password', 'ssn', 'phone', 'address', 'dob', 'credit card', 'card number', 'blood type', 'social security number'];
    const knownProcessors = ['twilio', 'sendgrid', 'stripe'];

    function isPiiField(keyName) {
        if (!keyName) return false;
        const spaced = keyName.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[^a-zA-Z0-9]/g, ' ').toLowerCase();
        return piiKeywords.some(k => {
            const regex = new RegExp(`\\b${k}\\b`, 'i');
            return regex.test(spaced);
        });
    }

    let processorInstances = new Set(knownProcessors);
    let processorWrappers = new Set();
    let processorMap = new Map();
    knownProcessors.forEach(p => processorMap.set(p, p));
    let piiAliases = new Map();

    function isProcessEnv(node) {
        if (!node) return false;
        if (node.type === 'MemberExpression') {
            if (node.object.type === 'Identifier' && node.object.name === 'process' && node.property.type === 'Identifier' && node.property.name === 'env') {
                return true;
            }
            return isProcessEnv(node.object);
        }
        return false;
    }

    function getPiiFieldFromExpression(node) {
        if (!node) return null;
        if (isProcessEnv(node)) return null;
        if (node.type === 'Identifier') {
            if (piiAliases.has(node.name)) return piiAliases.get(node.name);
            if (isPiiField(node.name)) {
                for (const k of piiKeywords) {
                    if (new RegExp(`\\b${k}\\b`, 'i').test(node.name.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase())) {
                        return k;
                    }
                }
                return node.name;
            }
        }
        if (node.type === 'MemberExpression') {
            if (node.property.type === 'Identifier') {
                if (isPiiField(node.property.name)) {
                    for (const k of piiKeywords) {
                        if (new RegExp(`\\b${k}\\b`, 'i').test(node.property.name.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase())) {
                            return k;
                        }
                    }
                    return node.property.name;
                }
                if (piiAliases.has(node.property.name)) return piiAliases.get(node.property.name);
            }
        }
        if (node.type === 'CallExpression') {
            for (const arg of node.arguments) {
                const found = getPiiFieldFromExpression(arg);
                if (found) return found;
            }
        }
        if (node.type === 'LogicalExpression' || node.type === 'BinaryExpression') {
            return getPiiFieldFromExpression(node.left) || getPiiFieldFromExpression(node.right);
        }
        if (node.type === 'ConditionalExpression') {
            return getPiiFieldFromExpression(node.consequent) || getPiiFieldFromExpression(node.alternate);
        }
        return null;
    }
    
    // PASS 1A: Order-independent processor instance discovery
    let addedNewInstance = true;
    while (addedNewInstance) {
        addedNewInstance = false;
        traverse(ast, {
            ImportDeclaration(path) {
                const source = path.node.source.value.toLowerCase();
                for (const proc of knownProcessors) {
                    if (source.includes(proc)) {
                        path.node.specifiers.forEach(spec => {
                            if (spec.local && spec.local.name && !processorInstances.has(spec.local.name)) {
                                processorInstances.add(spec.local.name);
                                processorMap.set(spec.local.name, proc);
                                addedNewInstance = true;
                            }
                        });
                    }
                }
            },
            VariableDeclarator(path) {
                if (path.node.init) {
                    let calls = [];
                    if (path.node.init.type === 'CallExpression') calls.push(path.node.init);
                    else if (path.node.init.type === 'ConditionalExpression') {
                        if (path.node.init.consequent && path.node.init.consequent.type === 'CallExpression') calls.push(path.node.init.consequent);
                        if (path.node.init.alternate && path.node.init.alternate.type === 'CallExpression') calls.push(path.node.init.alternate);
                    }
                    for (const call of calls) {
                        const callee = call.callee;
                        if (callee.type === 'Identifier' && callee.name === 'require') {
                            if (call.arguments.length > 0 && call.arguments[0].type === 'StringLiteral') {
                                const source = call.arguments[0].value.toLowerCase();
                                for (const proc of knownProcessors) {
                                    if (source.includes(proc) && path.node.id.type === 'Identifier' && !processorInstances.has(path.node.id.name)) {
                                        processorInstances.add(path.node.id.name);
                                        processorMap.set(path.node.id.name, proc);
                                        addedNewInstance = true;
                                    }
                                }
                            }
                        }
                        
                        if (callee.type === 'Identifier' && processorInstances.has(callee.name)) {
                            if (path.node.id.type === 'Identifier' && !processorInstances.has(path.node.id.name)) {
                                const baseProc = processorMap.get(callee.name) || callee.name;
                                processorInstances.add(path.node.id.name);
                                processorMap.set(path.node.id.name, baseProc);
                                addedNewInstance = true;
                            }
                        }
                    }
                }
            }
        });
    }

    // PASS 1B: Order-independent processor wrapper discovery
    let addedNewWrapper = true;
    while (addedNewWrapper) {
        addedNewWrapper = false;
        traverse(ast, {
            CallExpression(path) {
                let matchedProc = null;
                let callee = path.node.callee;
                
                if (callee.type === 'Identifier' && (processorInstances.has(callee.name) || processorWrappers.has(callee.name))) {
                    matchedProc = processorMap.get(callee.name) || callee.name;
                }
                if (callee.type === 'MemberExpression') {
                    let obj = callee.object;
                    while (obj && obj.type === 'MemberExpression') obj = obj.object;
                    if (obj && obj.type === 'Identifier' && (processorInstances.has(obj.name) || processorWrappers.has(obj.name))) {
                        matchedProc = processorMap.get(obj.name) || obj.name;
                    }
                }
                path.node.arguments.forEach(arg => {
                    if (arg.type === 'Identifier' && (processorInstances.has(arg.name) || processorWrappers.has(arg.name))) {
                        matchedProc = matchedProc || processorMap.get(arg.name) || arg.name;
                    }
                });

                if (matchedProc) {
                    const funcParent = path.getFunctionParent();
                    if (funcParent && funcParent.node.id && funcParent.node.id.name) {
                        if (!processorWrappers.has(funcParent.node.id.name)) {
                            processorWrappers.add(funcParent.node.id.name);
                            processorMap.set(funcParent.node.id.name, matchedProc);
                            addedNewWrapper = true;
                        }
                    }
                    if (funcParent && funcParent.parentPath && funcParent.parentPath.node.type === 'VariableDeclarator') {
                        if (funcParent.parentPath.node.id.type === 'Identifier') {
                            if (!processorWrappers.has(funcParent.parentPath.node.id.name)) {
                                processorWrappers.add(funcParent.parentPath.node.id.name);
                                processorMap.set(funcParent.parentPath.node.id.name, matchedProc);
                                addedNewWrapper = true;
                            }
                        }
                    }
                }
            }
        });
    }

    // PASS 2: Track variable/parameter aliases and extract data flows
    traverse(ast, {
        VariableDeclarator(path) {
            if (path.node.id && path.node.id.type === 'Identifier' && path.node.init) {
                const foundPii = getPiiFieldFromExpression(path.node.init);
                if (foundPii) {
                    piiAliases.set(path.node.id.name, foundPii);
                }
            }
        },
        CallExpression(path) {
            let callee = path.node.callee;

            // Parameter alias propagation on internal function calls
            if (callee.type === 'Identifier') {
                const funcBinding = path.scope.getBinding(callee.name);
                if (funcBinding && (funcBinding.path.isFunctionDeclaration() || funcBinding.path.isFunctionExpression())) {
                    const params = funcBinding.path.node.params;
                    path.node.arguments.forEach((arg, idx) => {
                        if (idx < params.length && params[idx].type === 'Identifier') {
                            const piiField = getPiiFieldFromExpression(arg);
                            if (piiField) {
                                piiAliases.set(params[idx].name, piiField);
                            }
                        }
                    });
                }
            }

            let isProcessorCall = false;
            let processorName = 'unknown-processor';

            if (callee.type === 'Identifier' && (processorInstances.has(callee.name) || processorWrappers.has(callee.name))) {
                isProcessorCall = true;
                processorName = processorMap.get(callee.name) || callee.name;
            }
            if (callee.type === 'MemberExpression') {
                let obj = callee.object;
                while (obj && obj.type === 'MemberExpression') obj = obj.object;
                if (obj && obj.type === 'Identifier' && (processorInstances.has(obj.name) || processorWrappers.has(obj.name))) {
                    isProcessorCall = true;
                    processorName = processorMap.get(obj.name) || obj.name;
                }
            }

            if (isProcessorCall) {
                path.node.arguments.forEach(arg => {
                    if (arg.type === 'ObjectExpression') {
                        arg.properties.forEach(prop => {
                            if (prop.type === 'ObjectProperty') {
                                let keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
                                let piiFromKey = isPiiField(keyName) ? keyName : null;
                                let piiFromVal = getPiiFieldFromExpression(prop.value);
                                let finalPii = piiFromKey || piiFromVal;

                                if (finalPii) {
                                    extraction.third_party_transfers.push({
                                        field: finalPii,
                                        processor: processorName,
                                        line: path.node.loc.start.line
                                    });
                                }
                            }
                        });
                    }
                    
                    const piiFromArg = getPiiFieldFromExpression(arg);
                    if (piiFromArg) {
                        extraction.third_party_transfers.push({
                            field: piiFromArg,
                            processor: processorName,
                            line: path.node.loc.start.line
                        });
                    }
                });
            }

            let isOutbound = false;
            if (callee.type === 'Identifier' && callee.name === 'fetch') {
                isOutbound = true;
            } else if (callee.type === 'MemberExpression') {
                if (callee.object && callee.object.name === 'axios') {
                    isOutbound = true;
                }
            } else if (callee.type === 'Identifier' && callee.name === 'axios') {
                isOutbound = true;
            }

            if (isOutbound && path.node.arguments.length > 0) {
                const arg = path.node.arguments[0];
                if (arg.type === 'StringLiteral') {
                    extraction.outbound_calls.push(arg.value);
                } else if (arg.type === 'TemplateLiteral') {
                    const quasis = arg.quasis.map(q => q.value.raw).join('${...}');
                    extraction.outbound_calls.push(quasis);
                }
            }
            
            if (callee.type === 'MemberExpression') {
                const objName = callee.object.name;
                const propName = callee.property.name;
                if ((objName === 'app' || objName === 'router') && ['get', 'post', 'put', 'patch', 'delete'].includes(propName)) {
                    if (path.node.arguments.length > 0 && path.node.arguments[0].type === 'StringLiteral') {
                        extraction.api_endpoints.push({
                            method: propName.toUpperCase(),
                            route: path.node.arguments[0].value,
                            line: path.node.loc.start.line
                        });
                    }
                }
            }
        },
        NewExpression(path) {
            const callee = path.node.callee;
            if (callee.type === 'MemberExpression' && callee.object.name === 'mongoose' && callee.property.name === 'Schema') {
                if (path.node.arguments.length > 0 && path.node.arguments[0].type === 'ObjectExpression') {
                    path.node.arguments[0].properties.forEach(prop => {
                        if (prop.type === 'ObjectProperty') {
                            let keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
                            if (isPiiField(keyName) && prop.value.type === 'ObjectExpression') {
                                let typeIsString = false;
                                prop.value.properties.forEach(innerProp => {
                                    if (innerProp.type === 'ObjectProperty' && innerProp.key.name === 'type') {
                                        if (innerProp.value.name === 'String') typeIsString = true;
                                    }
                                });
                                if (typeIsString) {
                                    extraction.unprotected_storage.push({
                                        field: keyName,
                                        line: prop.loc.start.line
                                    });
                                    // Add DB destination for consistency
                                    extraction.db_destinations.push({
                                        field: keyName,
                                        destination: "MongoDB",
                                        line: prop.loc.start.line
                                    });
                                }
                            }
                        }
                    });
                }
            }
        },
        VariableDeclarator(path) {
            if (path.node.id.type === 'ObjectPattern') {
                path.node.id.properties.forEach(prop => {
                    if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier') {
                        let keyName = prop.value.name;
                        if (isPiiField(keyName)) {
                            const binding = path.scope.getBinding(keyName);
                            if (binding && binding.references === 0) {
                                extraction.unused_pii_fields.push({
                                    field: keyName,
                                    line: prop.loc.start.line
                                });
                            }
                        }
                    }
                });
            }
        },
        ObjectProperty(path) {
            let keyName = null;
            if (path.node.key.type === 'Identifier') {
                keyName = path.node.key.name;
            } else if (path.node.key.type === 'StringLiteral') {
                keyName = path.node.key.value;
            }
            
            if (isPiiField(keyName)) {
                extraction.pii_fields.push({
                    field: keyName,
                    line: path.node.loc.start.line
                });
            }
        },
        JSXAttribute(path) {
            if (path.node.name && path.node.name.name === 'defaultChecked') {
                const hasValue = path.node.value === null || (path.node.value && path.node.value.type === 'JSXExpressionContainer' && path.node.value.expression.type === 'BooleanLiteral' && path.node.value.expression.value === true);
                if (hasValue) {
                     const parent = path.parent;
                     if (parent && parent.name && parent.name.name === 'input') {
                         const typeAttr = parent.attributes.find(a => a.name && a.name.name === 'type');
                         if (typeAttr && typeAttr.value && typeAttr.value.value === 'checkbox') {
                             extraction.pii_fields.push({
                                 field: "defaultChecked_checkbox",
                                 line: path.node.loc.start.line
                             });
                         }
                     }
                }
            }
        }
    });

    console.log(JSON.stringify(extraction));

} catch (err) {
    console.log(JSON.stringify({ error: err.message, file: filePath }));
}
