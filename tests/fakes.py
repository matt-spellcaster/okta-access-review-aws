"""Hand-written fakes for AWS clients, in the style of the existing FakeSession."""

import hashlib
import io


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Enough of boto3's S3 client for store.py: create-only puts, gets, listing."""

    def __init__(self, page_size=1000):
        self.objects = {}  # (bucket, key) -> bytes
        self.puts = []
        self.page_size = page_size
        self.fail_puts = None  # error code to raise on every put

    def put_object(self, Bucket, Key, Body, ContentType=None, IfNoneMatch=None, IfMatch=None,
                   ChecksumAlgorithm=None):
        self.puts.append({"Bucket": Bucket, "Key": Key, "IfNoneMatch": IfNoneMatch, "IfMatch": IfMatch,
                          "ChecksumAlgorithm": ChecksumAlgorithm})
        if self.fail_puts:
            raise FakeClientError(self.fail_puts)
        if IfNoneMatch == "*" and (Bucket, Key) in self.objects:
            raise FakeClientError("PreconditionFailed")
        if IfMatch is not None and self._etag(Bucket, Key) != IfMatch:
            raise FakeClientError("PreconditionFailed")
        self.objects[(Bucket, Key)] = bytes(Body)
        return {"ETag": self._etag(Bucket, Key)}

    def _etag(self, bucket, key):
        body = self.objects.get((bucket, key))
        return None if body is None else '"' + hashlib.md5(body).hexdigest() + '"'

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise FakeClientError("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)]), "ETag": self._etag(Bucket, Key)}

    def list_object_versions(self, Bucket, KeyMarker=None, VersionIdMarker=None):
        keys = sorted(k for b, k in self.objects if b == Bucket)
        return {"IsTruncated": False, "Versions": [{"Key": k, "VersionId": "v1"} for k in keys]}

    def delete_objects(self, Bucket, Delete, BypassGovernanceRetention=False):
        self.deletes = getattr(self, "deletes", []) + [(Bucket, BypassGovernanceRetention)]
        for obj in Delete["Objects"]:
            self.objects.pop((Bucket, obj["Key"]), None)
        return {}

    def list_objects_v2(self, Bucket, Prefix="", Delimiter=None, ContinuationToken=None):
        keys = sorted(k for b, k in self.objects if b == Bucket and k.startswith(Prefix))
        if Delimiter:
            entries = sorted({Prefix + k[len(Prefix):].split(Delimiter)[0] + Delimiter
                              for k in keys if Delimiter in k[len(Prefix):]})
        else:
            entries = keys
        start = int(ContinuationToken or 0)
        page = entries[start:start + self.page_size]
        more = start + self.page_size < len(entries)
        out = {"IsTruncated": more}
        if more:
            out["NextContinuationToken"] = str(start + self.page_size)
        if Delimiter:
            out["CommonPrefixes"] = [{"Prefix": p} for p in page]
        else:
            out["Contents"] = [{"Key": k} for k in page]
        return out


class FakeBot:
    """Records every Slack call the workflow makes."""

    def __init__(self):
        self.posts = []  # (channel, payload, ts)
        self.updates = []  # (channel, ts, payload)
        self.ephemeral = []  # (channel, user, text)
        self.modals = []
        self.uploads = []
        self._n = 0

    def open_dm(self, user):
        return "D" + user[1:]

    def post_message(self, channel, payload):
        self._n += 1
        ts = f"1758000000.{self._n:06d}"
        self.posts.append((channel, payload, ts))
        return ts

    def update_message(self, channel, ts, payload):
        self.updates.append((channel, ts, payload))

    def post_ephemeral(self, channel, user, text):
        self.ephemeral.append((channel, user, text))

    def open_modal(self, trigger_id, view):
        self.modals.append((trigger_id, view))

    def upload_file(self, channel, path, filename, title, thread_ts, comment):
        self.uploads.append((channel, filename, thread_ts, path.read_bytes()[:4]))


class FakeSfn:
    def __init__(self):
        self.successes = []

    def send_task_success(self, taskToken, output):
        self.successes.append((taskToken, output))
