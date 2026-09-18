import re
with open("src/compliance/js_ast_extractor.js", "r", encoding="utf-8") as f:
    text = f.read()

new_block = """                    if (arg.type === 'Identifier' && isPiiField(arg.name)) {
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
                    }"""

text = text.replace("""                    if (arg.type === 'Identifier' && isPiiField(arg.name)) {
                        extraction.third_party_transfers.push({
                            field: arg.name,
                            processor: processorName,
                            line: path.node.loc.start.line
                        });
                    }""", new_block)

with open("src/compliance/js_ast_extractor.js", "w", encoding="utf-8") as f:
    f.write(text)
