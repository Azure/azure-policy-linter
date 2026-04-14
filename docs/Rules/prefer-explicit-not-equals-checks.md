# Prefer Explicit Not Equals Checks


| Category | Identifier |
|----------------|----------------------------------------|
| BestPractices | prefer-explicit-not-equals-checks |

## Description

If you want a policy to ensure that some property is enabled or disabled, it is best practice to target resources where the property doesn't exist or is not the value that you want it to be, rather than check for some value that you think is the opposite of the value you want it to be. ie: if you want to ensure that some property is disabled. Rather than targeting resources that are enabled it is better to target all resources that are not explicitly disabled This helps to guard against random unexpected values being considered valid.

### Suggestions
Instead of 
```
{"field": "fieldName","equals":"Enabled"}
```
Format like 
```
{
    "anyOf": [
        {
            "exists": "false",
            "field": "fieldName"
        },
        {
            "field": "fieldName",
            "notEquals": "Disabled"
        }
    ]
}
```