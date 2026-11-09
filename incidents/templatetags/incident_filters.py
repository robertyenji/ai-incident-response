from django import template

register = template.Library()


@register.filter
def fmt_cat(value):
    """
    Convert snake_case category to Title Case with spaces.
    role_hijacking  →  Role Hijacking
    data_exfiltration  →  Data Exfiltration
    """
    if not value:
        return value
    return str(value).replace('_', ' ').title()
