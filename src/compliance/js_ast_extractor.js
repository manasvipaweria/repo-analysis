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
        db_destinations: []
    };

    const piiKeywords = ['email', 'password', 'ssn', 'phone', 'address', 'dob', 'credit card', 'card number', 'blood type', 'social security number'];

    function isPiiField(keyName) {
        if (!keyName) return false;
        // Normalize camelCase and special chars to spaces
        const spaced = keyName.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[^a-zA-Z0-9]/g, ' ').toLowerCase();
        
        return piiKeywords.some(k => {
            const regex = new RegExp(`\\b${k}\\b`, 'i');
            return regex.test(spaced);
        });
    }

    traverse(ast, {
        CallExpression(path) {
            const callee = path.node.callee;
            // Detect fetch() or axios()
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
            
            // Detect Express routing (app.get, router.post, etc)
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
        ObjectProperty(path) {
            // Detect potential PII fields in object definitions (e.g. models or payloads)
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
            // Check for defaultChecked={true} for consent
            if (path.node.name && path.node.name.name === 'defaultChecked') {
                if (path.node.value && path.node.value.type === 'JSXExpressionContainer' && path.node.value.expression.type === 'BooleanLiteral' && path.node.value.expression.value === true) {
                     // Check if it's a checkbox
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
    // Return empty on parse fail
    console.log(JSON.stringify({ error: err.message, file: filePath }));
}
