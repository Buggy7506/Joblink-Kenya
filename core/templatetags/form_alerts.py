from django import template
from django.contrib.messages import get_messages
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe

register = template.Library()


@register.simple_tag(takes_context=True)
def render_form_errors(context):
    request = context.get("request")
    form = context.get("form")
    flash_messages = list(get_messages(request)) if request else []
    html = render_to_string("form_errors.html", {
        "form": form,
        # Keep both names for compatibility across templates.
        "messages": flash_messages,
        "flash_messages": flash_messages,
    })
    return mark_safe(html)
