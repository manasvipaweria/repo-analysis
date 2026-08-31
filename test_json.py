import json
tests = [
    '{\n  "results": error',
    '{\n  "results": \nerror'
]
for t in tests:
    try:
        json.loads(t)
    except json.JSONDecodeError as e:
        print(repr(t), "=>", e)
