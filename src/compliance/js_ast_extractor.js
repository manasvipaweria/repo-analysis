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
    
    // PASS 1: Identify processor instances and wrappers
    traverse(ast, {
        ImportDeclaration(path) {
            const source = path.node.source.value.toLowerCase();
            for (const proc of knownProcessors) {
                if (source.includes(proc)) {
                    path.node.specifiers.forEach(spec => {
                        if (spec.local && spec.local.name) {
                            processorInstances.add(spec.local.name);
                        }
                    });
                }
            }
        },
        VariableDeclarator(path) {
            if (path.node.init && path.node.init.type === 'CallExpression') {
                const callee = path.node.init.callee;
                if (callee.type === 'Identifier' && callee.name === 'require') {
                    if (path.node.init.arguments.length > 0 && path.node.init.arguments[0].type === 'StringLiteral') {
                        const source = path.node.init.arguments[0].value.toLowerCase();
                        for (const proc of knownProcessors) {
                            if (source.includes(proc) && path.node.id.type === 'Identifier') {
                                processorInstances.add(path.node.id.name);
                            }
                        }
                    }
                }
                
                if (callee.type === 'Identifier' && processorInstances.has(callee.name)) {
                    if (path.node.id.type === 'Identifier') {
                        processorInstances.add(path.node.id.name);
                    }
                }
            }
        },
        CallExpression(path) {
            let isProcessorCall = false;
            let callee = path.node.callee;
            
            if (callee.type === 'Identifier' && processorInstances.has(callee.name)) {
                isProcessorCall = true;
            }
            if (callee.type === 'MemberExpression') {
                let obj = callee.object;
                while (obj && obj.type === 'MemberExpression') obj = obj.object;
                if (obj && obj.type === 'Identifier' && processorInstances.has(obj.name)) {
                    isProcessorCall = true;
                }
            }
            
            if (isProcessorCall) {
                const funcParent = path.getFunctionParent();
                if (funcParent && funcParent.node.id && funcParent.node.id.name) {
                    processorWrappers.add(funcParent.node.id.name);
                }
                if (funcParent && funcParent.parentPath && funcParent.parentPath.node.type === 'VariableDeclarator') {
                    if (funcParent.parentPath.node.id.type === 'Identifier') {
                        processorWrappers.add(funcParent.parentPath.node.id.name);
                    }
                }
            }
        }
    });

    // PASS 2: Extract data flows
    traverse(ast, {
        CallExpression(path) {
            let isProcessorCall = false;
            let callee = path.node.callee;
            let processorName = 'unknown-processor';

            if (callee.type === 'Identifier' && (processorInstances.has(callee.name) || processorWrappers.has(callee.name))) {
                isProcessorCall = true;
                processorName = callee.name;
                if (processorWrappers.has(callee.name)) {
                    processorName = `wrapper[${callee.name}]`;
                }
            }
            if (callee.type === 'MemberExpression') {
                let obj = callee.object;
                while (obj && obj.type === 'MemberExpression') obj = obj.object;
                if (obj && obj.type === 'Identifier' && (processorInstances.has(obj.name) || processorWrappers.has(obj.name))) {
                    isProcessorCall = true;
                    processorName = obj.name;
                    if (processorWrappers.has(obj.name)) {
                         processorName = `wrapper[${obj.name}]`;
                    }
                }
            }

            if (isProcessorCall) {
                path.node.arguments.forEach(arg => {
                    if (arg.type === 'ObjectExpression') {
                        arg.properties.forEach(prop => {
                            if (prop.type === 'ObjectProperty') {
                                let keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
                                if (isPiiField(keyName)) {
                                    extraction.third_party_transfers.push({
                                        field: keyName,
                                        processor: processorName,
                                        line: path.node.loc.start.line
                                    });
                                }
                            }
                        });
                    }
                    if (arg.type === 'Identifier' && isPiiField(arg.name)) {
                        extraction.third_party_transfers.push({
                            field: arg.name,
                            processor: processorName,
                            line: path.node.loc.start.line
                        });
                    }
                    if (arg.type === 'MemberExpression' && arg.property.type === 'Identifier' && isPiiField(arg.property.name)) {
                        extraction.third_party_transfers.push({
                            field: arg.property.name,
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
