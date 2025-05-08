package main

required_tags := {"Environment", "Owner", "Project"}

# Deny if any resource is missing required tags
deny[msg] {
    resource := input.resource_changes[_]
    tags := resource.change.after.tags
    missing := missing_tags(tags, required_tags)
    count(missing) > 0
    msg := sprintf(
        "Resource '%s' (%s) is missing required tags: %v",
        [resource.name, resource.type, missing]
    )
}