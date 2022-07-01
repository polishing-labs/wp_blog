{% extends '_layout.swig' %}
{% import '_macro/sidebar.swig' as sidebar_template with context %}

{% block title %}{{ title }}{%- if theme.index_with_subtitle and subtitle %} - {{ subtitle }}{%- endif %}{% endblock %}

{% block class %}index posts-expand{% endblock %}

{% block content %}

  {%- for post in page.posts.toArray() %}
    {{ partial('_macro/post.swig', {post: post, is_index: true}) }}
  {%- endfor %}

  {% include '_partials/pagination.swig' %}

{% endblock %}
<script async defer data-website-id="9aab3793-bf4f-4055-8c11-e23ab244a0d0" src="https://analyze.timochan.cn/umami.js"></script>
{% block sidebar %}
  {{ sidebar_template.render(false) }}
{% endblock %}
