from django import template
from django.contrib.messages import get_messages

register = template.Library()


@register.inclusion_tag("form_errors.html", takes_context=True)
def render_form_errors(context):
    request = context.get("request")
    form = context.get("form")
    flash_messages = list(get_messages(request)) if request else []
    return {
        "form": form,
        # Keep both names for compatibility across templates.
        "messages": flash_messages,
        "flash_messages": flash_messages,
    }
