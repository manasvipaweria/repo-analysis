import re
with open("src/compliance/js_ast_extractor.js", "r", encoding="utf-8") as f:
    text = f.read()

old_jsx = """        JSXAttribute(path) {
            if (path.node.name && path.node.name.name === 'defaultChecked') {
                if (path.node.value && path.node.value.type === 'JSXExpressionContainer' && path.node.value.expression.type === 'BooleanLiteral' && path.node.value.expression.value === true) {"""
                
new_jsx = """        JSXAttribute(path) {
            if (path.node.name && path.node.name.name === 'defaultChecked') {
                const hasValue = path.node.value === null || (path.node.value && path.node.value.type === 'JSXExpressionContainer' && path.node.value.expression.type === 'BooleanLiteral' && path.node.value.expression.value === true);
                if (hasValue) {"""

text = text.replace(old_jsx, new_jsx)

with open("src/compliance/js_ast_extractor.js", "w", encoding="utf-8") as f:
    f.write(text)
