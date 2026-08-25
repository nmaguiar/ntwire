# {{portal.title}}

Welcome to the internal services portal{{#if user.display_name}}, **{{user.display_name}}**{{/if}}!

> **Environment:** {{variables.environment}}  
> **Status:** All systems operational.

---

{{#each categories}}
## {{name}}

{{#each targets}}
### {{name}}
{{description}}

{{#if url}}
{{#if capability.open_socks_browser}}
[Open in Isolated Browser](ntwire://open/{{id}})
{{/if}}
{{#if capability.web_portal}}
[Open Service Webpage]({{url}})
{{/if}}
{{/if}}

{{#if connection_instructions}}
**Connection Instructions:**
{{connection_instructions}}
{{/if}}

{{/each}}
{{/each}}

---

### Quick Reference

| Service | Category | Port |
| --- | --- | --- |
{{#each targets}}
| {{name}} | {{category}} | `{{virtual_port}}` |
{{/each}}

<sub>Rendered securely by ntwire Portal. Only authorized services for your identity are listed above.</sub>
