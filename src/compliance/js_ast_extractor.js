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
    
    let activeProcessors = new Set();
    
    traverse(ast, {
        ImportDeclaration(path) {
            const source = path.node.source.value.toLowerCase();
            for (const proc of knownProcessors) {
                if (source.includes(proc)) activeProcessors.add(proc);
            }
        },
        CallExpression(path) {
            const callee = path.node.callee;
            // Require calls
            if (callee.type === 'Identifier' && callee.name === 'require') {
                if (path.node.arguments.length > 0 && path.node.arguments[0].type === 'StringLiteral') {
                    const source = path.node.arguments[0].value.toLowerCase();
                    for (const proc of knownProcessors) {
                        if (source.includes(proc)) activeProcessors.add(proc);
                    }
                }
            }
            
            let calledProcessor = null;
            if (callee.type === 'MemberExpression' && callee.object && callee.object.name) {
                 const objName = callee.object.name.toLowerCase();
                 if (knownProcessors.includes(objName)) {
                     calledProcessor = objName;
                 }
            }
            
            if (calledProcessor || activeProcessors.size > 0) {
                const processor = calledProcessor || Array.from(activeProcessors)[0];
                path.node.arguments.forEach(arg => {
                    if (arg.type === 'ObjectExpression') {
                        arg.properties.forEach(prop => {
                            if (prop.type === 'ObjectProperty') {
                                let keyName = prop.key.name || (prop.key.type === 'StringLiteral' ? prop.key.value : null);
                                if (isPiiField(keyName)) {
                                    extraction.third_party_transfers.push({
                                        field: keyName,
                                        processor: processor,
                                        line: path.node.loc.start.line
                                    });
                                }
                            }
                        });
                    }
                    if (arg.type === 'Identifier' && isPiiField(arg.name)) {
                        extraction.third_party_transfers.push({
                            field: arg.name,
                            processor: processor,
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
                if (path.node.value && path.node.value.type === 'JSXExpressionContainer' && path.node.value.expression.type === 'BooleanLiteral' && path.node.value.expression.value === true) {
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
