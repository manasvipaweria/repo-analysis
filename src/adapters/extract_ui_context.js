const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const filePath = process.argv[2];
if (!filePath) {
    console.error("Usage: node extract_ui_context.js <file>");
    process.exit(1);
}

const code = fs.readFileSync(filePath, 'utf-8');
const codeLines = code.split('\n');

let ast;
try {
    ast = parser.parse(code, {
        sourceType: "module",
        plugins: ["jsx", "typescript"]
    });
} catch (e) {
    console.error("Parse error:", e.message);
    process.exit(1);
}

// Keep only semantic elements or elements with meaningful classes/attributes
const MEANINGFUL_TAGS = new Set([
    "button", "input", "form", "a", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "th", "tr", "td", "img", "nav", "ul", "li", "dialog"
]);

function extractJsxHierarchy(node, depth = 0) {
    if (!node || depth > 20) return null; // Avoid infinite loops/stack overflow
    
    if (node.type === "JSXElement") {
        const nameNode = node.openingElement.name;
        let name = "Unknown";
        if (nameNode.type === "JSXIdentifier") name = nameNode.name;
        else if (nameNode.type === "JSXMemberExpression") {
            name = nameNode.object.name + "." + nameNode.property.name;
        }

        const isComponent = name.match(/^[A-Z]/);
        let hasMeaningfulAttrs = false;
        
        const attrs = {};
        node.openingElement.attributes.forEach(attr => {
            if (attr.type === "JSXAttribute" && attr.name) {
                const attrName = attr.name.name;
                if (["className", "id", "onClick", "onChange", "onSubmit"].includes(attrName)) {
                    hasMeaningfulAttrs = true;
                    if (attr.value) {
                        if (attr.value.type === "StringLiteral") {
                            attrs[attrName] = attr.value.value;
                        } else if (attr.value.type === "JSXExpressionContainer") {
                            if (attr.value.expression.type === "Identifier") {
                                attrs[attrName] = `{${attr.value.expression.name}}`;
                            } else if (attr.value.expression.type === "ArrowFunctionExpression" || attr.value.expression.type === "FunctionExpression") {
                                attrs[attrName] = `{inline_function}`;
                            } else {
                                attrs[attrName] = "{expression}";
                            }
                        }
                    } else {
                        attrs[attrName] = true;
                    }
                }
            }
        });

        // Determine if we should include this node in the compact tree
        const shouldInclude = isComponent || MEANINGFUL_TAGS.has(name.toLowerCase()) || hasMeaningfulAttrs;

        const children = [];
        node.children.forEach(child => {
            const childNode = extractJsxHierarchy(child, depth + 1);
            if (childNode) {
                if (Array.isArray(childNode)) {
                    children.push(...childNode);
                } else {
                    children.push(childNode);
                }
            }
        });

        if (shouldInclude) {
            return { type: "element", name, attributes: attrs, children };
        } else {
            // Flatten: pull children up
            return children;
        }
    } else if (node.type === "JSXFragment") {
        const children = [];
        node.children.forEach(child => {
            const childNode = extractJsxHierarchy(child, depth + 1);
            if (childNode) {
                if (Array.isArray(childNode)) children.push(...childNode);
                else children.push(childNode);
            }
        });
        return children;
    } else if (node.type === "JSXExpressionContainer") {
        // e.g., {loading && <Spinner />}
        // Try to identify what state controls it
        let condition = "conditional";
        if (node.expression.type === "LogicalExpression" && node.expression.left.type === "Identifier") {
            condition = node.expression.left.name;
        } else if (node.expression.type === "ConditionalExpression" && node.expression.test.type === "Identifier") {
            condition = node.expression.test.name;
        }

        let nestedJsx = [];
        traverse(node, {
            noScope: true,
            JSXElement(path) {
                const childNode = extractJsxHierarchy(path.node, depth + 1);
                if (childNode) {
                    if (Array.isArray(childNode)) nestedJsx.push(...childNode);
                    else nestedJsx.push(childNode);
                }
                path.skip();
            },
            JSXFragment(path) {
                const childNode = extractJsxHierarchy(path.node, depth + 1);
                if (childNode) {
                    if (Array.isArray(childNode)) nestedJsx.push(...childNode);
                    else nestedJsx.push(childNode);
                }
                path.skip();
            }
        }, null, {});
        
        if (nestedJsx.length > 0) {
            return { type: "conditional", condition, children: nestedJsx };
        }
    }
    return null;
}

const components = [];

traverse(ast, {
    FunctionDeclaration(path) {
        processComponent(path);
    },
    VariableDeclarator(path) {
        if (path.node.init && (path.node.init.type === "ArrowFunctionExpression" || path.node.init.type === "FunctionExpression")) {
            processComponent(path);
        }
    }
});

function getLoc(node) {
    if (!node.loc) return { start: 0, end: 0 };
    return { start: node.loc.start.line, end: node.loc.end.line };
}

function processComponent(path) {
    let name = "Anonymous";
    if (path.node.type === "FunctionDeclaration" && path.node.id) {
        name = path.node.id.name;
    } else if (path.node.type === "VariableDeclarator" && path.node.id) {
        name = path.node.id.name;
    }

    let hasJsx = false;
    let jsxTrees = [];
    
    const states = [];
    const actions = [];

    path.traverse({
        JSXElement(jsxPath) {
            hasJsx = true;
            if (jsxPath.parentPath.isReturnStatement() || jsxPath.parentPath.isArrowFunctionExpression()) {
                const tree = extractJsxHierarchy(jsxPath.node);
                if (tree) {
                    if (Array.isArray(tree)) jsxTrees.push(...tree);
                    else jsxTrees.push(tree);
                }
            }
        },
        JSXFragment(jsxPath) {
            hasJsx = true;
            if (jsxPath.parentPath.isReturnStatement() || jsxPath.parentPath.isArrowFunctionExpression()) {
                const tree = extractJsxHierarchy(jsxPath.node);
                if (tree) {
                    if (Array.isArray(tree)) jsxTrees.push(...tree);
                    else jsxTrees.push(tree);
                }
            }
        },
        CallExpression(callPath) {
            if (callPath.node.callee.name === "useState") {
                if (callPath.parentPath.isVariableDeclarator() && callPath.parentPath.node.id.type === "ArrayPattern") {
                    const elements = callPath.parentPath.node.id.elements;
                    if (elements.length > 0 && elements[0]) {
                        states.push(elements[0].name);
                    }
                }
            }
        },
        FunctionDeclaration(funcPath) {
            if (funcPath.node.id) actions.push(funcPath.node.id.name);
        },
        VariableDeclarator(varPath) {
            if (varPath.node.init && (varPath.node.init.type === "ArrowFunctionExpression" || varPath.node.init.type === "FunctionExpression")) {
                if (varPath.node.id) actions.push(varPath.node.id.name);
            }
        }
    });

    if (hasJsx) {
        const loc = getLoc(path.node);
        // Only extract the source excerpt if the component is reasonably small, or we just extract the first few lines as signature
        const signature = codeLines.slice(loc.start - 1, loc.start + 5).join("\n") + "\n...";

        components.push({
            name,
            line_range: [loc.start, loc.end],
            signature,
            state: states,
            actions: actions.filter(a => a !== name && !a.match(/^[A-Z]/)),
            ui_hierarchy: jsxTrees
        });
    }
}

// Convert JSON representation to text map
let mapOutput = "";

function printTree(nodes, depth = 0) {
    let out = "";
    const indent = " ".repeat(depth * 2);
    for (const node of nodes) {
        if (!node) continue;
        if (node.type === "element") {
            let attrStr = "";
            for (const [k, v] of Object.entries(node.attributes)) {
                if (k === "className") attrStr += ` className="${v}"`;
                else attrStr += ` ${k}=${v}`;
            }
            out += `${indent}├── <${node.name}${attrStr}>\n`;
            if (node.children && node.children.length > 0) {
                out += printTree(node.children, depth + 1);
            }
        } else if (node.type === "conditional") {
            out += `${indent}├── [Condition: ${node.condition}]\n`;
            if (node.children && node.children.length > 0) {
                out += printTree(node.children, depth + 1);
            }
        }
    }
    return out;
}

for (const comp of components) {
    mapOutput += `Component: ${comp.name} (Lines: ${comp.line_range[0]}-${comp.line_range[1]})\n`;
    mapOutput += `Signature:\n${comp.signature}\n`;
    if (comp.state.length > 0) mapOutput += `State: ${comp.state.join(", ")}\n`;
    if (comp.actions.length > 0) mapOutput += `Actions: ${comp.actions.join(", ")}\n`;
    mapOutput += `UI Hierarchy:\n`;
    mapOutput += printTree(comp.ui_hierarchy, 1);
    mapOutput += `\n----------------------------------------\n`;
}

console.log(mapOutput);
