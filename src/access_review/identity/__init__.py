"""The source-agnostic identity layer: principals, credentials, grants and the
evidenced links between them. See model.py for why it composes above
`Snapshot` rather than replacing or extending it."""

from .graph import (
    METHOD_ORDER,
    Coverage,
    Credential,
    CredentialKind,
    Grant,
    GrantKind,
    Identity,
    IdentityGraph,
    Link,
    LinkMethod,
    Principal,
    PrincipalKey,
    PrincipalKind,
    SourceMeta,
    Status,
)
from .github import GitHubSnapshot, project_github, source_name
from .okta import OKTA, project_snapshot

__all__ = [
    "METHOD_ORDER",
    "OKTA",
    "Coverage",
    "Credential",
    "CredentialKind",
    "GitHubSnapshot",
    "Grant",
    "GrantKind",
    "Identity",
    "IdentityGraph",
    "Link",
    "LinkMethod",
    "Principal",
    "PrincipalKey",
    "PrincipalKind",
    "SourceMeta",
    "source_name",
    "Status",
    "project_github",
    "project_snapshot",
]
