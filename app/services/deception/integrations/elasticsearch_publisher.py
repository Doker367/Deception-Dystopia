"""Compatibility import for the Elasticsearch publisher.

Implementation lives in ``elastic_svc`` next to the other integration
services. Importing this module performs no I/O and opens no connection.
"""

from .elastic_svc import (  # noqa: F401
    DocumentConflict,
    ElasticPublisher,
    ElasticsearchConfig,
    PublisherDisabled,
)

__all__ = [
    "DocumentConflict",
    "ElasticPublisher",
    "ElasticsearchConfig",
    "PublisherDisabled",
]
