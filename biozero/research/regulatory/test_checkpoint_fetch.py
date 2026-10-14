"""Offline downloader policy tests; no checkpoint acquisition or Torch loading."""
import email.message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("checkpoint_fetch", HERE / "checkpoint_fetch.py")
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class Response(io.BytesIO):
    def __init__(self,body=b"",mime="application/octet-stream",length=None,url="https://drive.google.com/uc"):
        super().__init__(body)
        self.headers=email.message.Message()
        self.headers["Content-Type"]=mime
        if length is not None:
            self.headers["Content-Length"]=str(length)
        self.url=url
    def geturl(self):
        return self.url


class FakeOpener:
    def __init__(self,responses):
        self.responses=list(responses)
        self.requests=[]
    def open(self,request,timeout):
        self.requests.append(request)
        result=self.responses.pop(0)
        if isinstance(result,BaseException):
            raise result
        return result


def entry(body=b"checkpoint"):
    return {"component":"test","filename":"test.pth","size_bytes":len(body),
            "sha256":hashlib.sha256(body).hexdigest(),"drive_id":"abcdefghijklmno"}


class DownloaderTests(unittest.TestCase):
    def test_manifest_five_pins_and_total(self):
        manifest=fetch.load_manifest()
        self.assertEqual(len(manifest["files"]),5)
        self.assertEqual(manifest["total_checkpoint_bytes"],400312985)
        self.assertEqual(manifest["source_repository"],"https://github.com/kostkalab/seillra.git")
        with tempfile.TemporaryDirectory() as root:
            manifest["files"][0]["sha256"]="0"*64
            path=Path(root)/"manifest.json";path.write_text(json.dumps(manifest))
            with self.assertRaises(fetch.FetchError):
                fetch.load_manifest(path)

    def test_https_allowlist_rejects_external_and_credentials(self):
        for url in ("http://drive.google.com/uc","https://evil.example/file",
                    "https://drive.google.com.evil.example/uc","https://accounts.google.com/login",
                    "https://secret@drive.google.com/uc","https://drive.google.com:444/uc"):
            with self.subTest(url=url),self.assertRaises(fetch.FetchError):
                fetch.allowed_url(url)
        for url in ("https://drive.google.com/uc","https://drive.usercontent.google.com/download",
                    "https://doc-123.googleusercontent.com/file"):
            self.assertEqual(fetch.allowed_url(url),url)

    def test_persistent_ledger_reconciles_actual_reads_and_never_resets(self):
        with tempfile.TemporaryDirectory() as root:
            with fetch.TransferLedger(root,limit=100) as ledger:
                client=fetch.DownloadClient(ledger,time.monotonic()+10,FakeOpener([]))
                self.assertEqual(client.read(Response(b"123"),50),b"123")
                self.assertEqual(ledger.data["charged_bytes"],3)
                self.assertEqual(ledger.data["body_bytes_observed"],3)
                ledger.charge(40) # simulate interruption after a read reservation
            with fetch.TransferLedger(root,limit=100) as ledger:
                self.assertEqual(ledger.data["charged_bytes"],43)
                with self.assertRaises(fetch.FetchError):
                    ledger.charge(58)
                self.assertEqual(ledger.data["charged_bytes"],43)
            with self.assertRaises(fetch.FetchError):
                fetch.TransferLedger(root,limit=99)

    def test_html_confirmation_is_bounded_and_restricted(self):
        html=b'<form action="https://drive.usercontent.google.com/download" method="get"><input type="hidden" name="id" value="abcdefghijklmno"><input type="hidden" name="confirm" value="t"></form>'
        url=fetch.confirmation_url(html,"https://drive.google.com/uc","abcdefghijklmno")
        self.assertIn("confirm=t",url)
        with self.assertRaises(fetch.FetchError):
            fetch.confirmation_url(html.replace(b"drive.usercontent.google.com",b"evil.example"),"https://drive.google.com/uc","abcdefghijklmno")
        with self.assertRaises(fetch.FetchError):
            fetch.confirmation_url(b"x"*(fetch.MAX_HTML+1),"https://drive.google.com/uc","abcdefghijklmno")

    def test_verified_atomic_file_and_cache_make_no_extra_network(self):
        with tempfile.TemporaryDirectory() as root:
            item=entry();opener=FakeOpener([Response(length=item["size_bytes"]),Response(b"checkpoint",length=item["size_bytes"])])
            def factory(ledger,deadline):
                return fetch.DownloadClient(ledger,deadline,opener)
            with fetch.TransferLedger(root) as ledger:
                result=fetch.fetch_file(item,root,ledger,factory)
                self.assertEqual(result["status"],"verified")
                self.assertEqual(ledger.data["charged_bytes"],len(b"checkpoint"))
                self.assertEqual(ledger.data["body_bytes_observed"],len(b"checkpoint"))
                result=fetch.fetch_file(item,root,ledger,factory)
                self.assertEqual(result["status"],"verified_cached")
                self.assertEqual(len(opener.requests),2)
            self.assertEqual([x.name for x in (Path(root)/"checkpoints").iterdir()],["test.pth"])
            self.assertEqual((Path(root)/"checkpoints"/"test.pth").stat().st_mode & 0o777,0o600)

    def test_checksum_failure_charges_body_and_discards_partial(self):
        with tempfile.TemporaryDirectory() as root:
            item=entry(b"good");opener=FakeOpener([Response(length=4),Response(b"evil",length=4)])
            with fetch.TransferLedger(root) as ledger:
                with self.assertRaises(fetch.FetchError):
                    fetch.fetch_file(item,root,ledger,lambda l,d:fetch.DownloadClient(l,d,opener))
                self.assertEqual(ledger.data["body_bytes_observed"],4)
                self.assertEqual(ledger.data["attempts"][0]["status"],"failed")
            self.assertEqual(list((Path(root)/"checkpoints").iterdir()),[])

    def test_http_error_body_is_accounted_without_retry(self):
        with tempfile.TemporaryDirectory() as root,fetch.TransferLedger(root) as ledger:
            headers=email.message.Message();headers["Content-Type"]="text/html"
            error=urllib.error.HTTPError("https://drive.google.com/uc",503,"failed",headers,io.BytesIO(b"service unavailable"))
            opener=FakeOpener([error]);client=fetch.DownloadClient(ledger,time.monotonic()+10,opener)
            with self.assertRaises(fetch.FetchError):
                client.open("https://drive.google.com/uc")
            self.assertEqual(ledger.data["body_bytes_observed"],len(b"service unavailable"))
            self.assertEqual(len(opener.requests),1)

    def test_content_larger_than_pin_is_rejected_before_publish(self):
        with tempfile.TemporaryDirectory() as root:
            item=entry(b"good");opener=FakeOpener([Response(),Response(b"goodextra")])
            with fetch.TransferLedger(root) as ledger:
                with self.assertRaises(fetch.FetchError):
                    fetch.fetch_file(item,root,ledger,lambda l,d:fetch.DownloadClient(l,d,opener))
                self.assertEqual(ledger.data["body_bytes_observed"],5)
            self.assertEqual(list((Path(root)/"checkpoints").iterdir()),[])

    def test_short_reads_reconcile_one_window_without_fragment_fsyncs(self):
        class ShortReads(Response):
            def __init__(self,body):
                super().__init__(body)
                self.calls=0
            def read1(self,size):
                self.calls+=1
                return super().read1(min(size,7))
        with tempfile.TemporaryDirectory() as root,fetch.TransferLedger(root) as ledger:
            writes=[]
            original=ledger.save
            def save():
                writes.append(1)
                original()
            ledger.save=save
            body=b"x"*20000
            response=ShortReads(body)
            client=fetch.DownloadClient(ledger,time.monotonic()+10,FakeOpener([]))
            self.assertEqual(client.read(response,65536),body)
            self.assertGreater(response.calls,2000)
            self.assertEqual(len(writes),2)
            self.assertEqual(ledger.data["charged_bytes"],len(body))
            self.assertEqual(ledger.data["body_bytes_observed"],len(body))

    def test_interrupted_read_counts_returned_fragments_and_keeps_reservation(self):
        class Interrupted(Response):
            def read1(self,size):
                if self.tell():
                    raise OSError("socket failure")
                return super().read1(min(size,2))
        with tempfile.TemporaryDirectory() as root,fetch.TransferLedger(root) as ledger:
            client=fetch.DownloadClient(ledger,time.monotonic()+10,FakeOpener([]))
            with self.assertRaises(OSError):
                client.read(Interrupted(b"data"),100)
            self.assertEqual(ledger.data["charged_bytes"],100)
            self.assertEqual(ledger.data["body_bytes_observed"],2)
            data=json.loads(ledger.path.read_text())
            self.assertEqual(data["charged_bytes"],100)
            self.assertEqual(data["body_bytes_observed"],2)

    def test_redirect_handler_does_not_read_unbounded_body(self):
        class NoRead(Response):
            def read(self,*unused):
                raise AssertionError("redirect body read")
        class Client:
            redirects=0
            def open(self,url,method):
                return (url,method)
        import urllib.request
        client=Client();handler=fetch.BoundedRedirect(client)
        headers=email.message.Message();headers["Location"]="https://drive.usercontent.google.com/download"
        response=NoRead(b"x"*1000000)
        result=handler.http_error_302(urllib.request.Request("https://drive.google.com/uc"),response,302,"redirect",headers)
        self.assertEqual(result[0],headers["Location"])
        self.assertTrue(response.closed)


if __name__=="__main__":
    unittest.main()
