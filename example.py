import powerprotect

test = powerprotect.ProtectionRule(name='testing', server='ppdm.bluehairfreak.com', password="Password#1")

protection_policy = test.get_protection_policy_by_name('test')

print(protection_policy.__dict__)

body = {'action': 'MOVE_TO_GROUP',
'name': 'sampl',
'actionResult': 'c94985c1-2805-4e40-b1ba-6fdc6a01c3e1',
'conditions': [{
'assetAttributeName': 'userTags',
'operator': 'EQUALS',
'assetAttributeValue': 'test=test'
}],
'connditionConnector': 'AND',
'inventorySourceType': 'KUBERNETESs',
'priority': 1,
'tenant': {
'id': '00000000-0000-4000-a000-000000000000'
}
}

response = test._rest_post("/protection-rules", body)

print(response.__dict__)
