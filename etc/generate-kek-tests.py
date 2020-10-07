import json
keks = {
    "aws": {
        "template": {
            "provider": "aws",
            "key": "example arn",
            "region": "example region",
            "endpoint": "example.com"
        },
        "optional": [ "endpoint" ],
        "endpoints": [ "endpoint" ]
    },
    "local": {
        "template": {
            "provider": "local"
        }
    },
    "azure": {
        "template": {
            "provider": "azure",
            "keyVaultEndpoint": "keyvault.example.com",
            "keyName": "example keyName",
            "keyVersion": "example keyVersion"
        },
        "optional": [ "keyVersion" ],
        "endpoints": [ "keyVaultEndpoint" ]
    },
    "gcp": {
        "template": {
            "provider": "gcp",
            "projectId": "example projectId",
            "location": "example location",
            "keyRing": "example keyRing",
            "keyName": "example keyName",
            "keyVersion": "example keyVersion",
            "endpoint": "example.com"
        },
        "optional": [ "endpoint", "keyVersion" ],
        "endpoints": [ "endpoint" ]
    }
}

testcases = []
def add_testcase (input, expect):
    testcases.append ({
        "input": input,
        "expect": expect
    })

for name, kek in keks.items():
    # Add successful case.
    add_testcase (kek["template"], "ok")

    # Test that endpoints are validated.
    if "endpoints" in kek:
        testcase = kek["template"].copy()
        for endpoint in kek["endpoints"]:
            testcase[endpoint] = "invalid endpoint"
            add_testcase (testcase, "invalid endpoint")

    # Test with all optional fields removed.
    if "optional" in kek:
        testcase = {}
        for k,v in kek["template"].items():
            if k not in kek["optional"]:
                testcase[k] = v
        add_testcase (testcase, "ok")

print (json.dumps(testcases, indent=4))