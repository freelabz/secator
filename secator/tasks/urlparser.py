from urllib.parse import urlparse, urlunparse, parse_qs

from secator.decorators import task
from secator.definitions import URL
from secator.output_types import Tag, Url
from secator.runners import PythonRunner


@task()
class urlparser(PythonRunner):
    """Extract query string parameters from URLs"""
    input_types = [URL]
    output_types = [Tag, Url]
    tags = ['url', 'params']
    opts = {
        'include': {
            'type': list,
            'default': ['url', 'url_root', 'url_base', 'url_query', 'url_param'],
            'help': 'Include the specified parts in the output'
        },
    }

    def yielder(self):
        root_urls = set()
        base_urls = set()
        for input in self.inputs:
            include = self.run_opts.get('include', [])
            if 'url' in include:
                yield Url(url=input)
            parsed_url = urlparse(input)
            base_url = urlunparse(parsed_url._replace(query=''))
            root_url = urlunparse(parsed_url._replace(query='', fragment='', path=''))
            query = parsed_url.query
            if 'url_root' in include and root_url not in root_urls:
                yield Tag(category='info', name='url_root', value=root_url, match=base_url)
                root_urls.add(root_url)
            if 'url_base' in include and base_url not in base_urls:
                yield Tag(category='info', name='url_base', value=base_url, match=base_url)
                base_urls.add(base_url)
            if 'url_query' in include:
                yield Tag(category='info', name='url_query', value=query, match=base_url)
            if 'url_param' in include:
                params = parse_qs(parsed_url.query)
                for param_name, param_value in params.items():
                    yield Tag(
                        category='info',
                        name='url_param',
                        value=param_name,
                        match=base_url,
                        extra_data={'value': param_value[0], 'url': input}
                    )
