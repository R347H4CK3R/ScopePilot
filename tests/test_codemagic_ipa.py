from pathlib import Path
import json
import plistlib
import struct
import subprocess
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
class IPATests(unittest.TestCase):
    def test_verification_is_fail_closed(self):
        for repo in ['current']:
            for fault in [None,'identity','asset','architecture','platform','minimum-os']:
                with self.subTest(repo=repo,fault=fault),tempfile.TemporaryDirectory() as tmp:
                    d=Path(tmp); (d/'web').mkdir();(d/'web/index.html').write_bytes(b'actual-source')
                    info={'CFBundleIdentifier':'app.test' if fault!='identity' else 'wrong','CFBundleExecutable':'Test','CFBundleShortVersionString':'1.0','CFBundleVersion':'1','CFBundleSupportedPlatforms':['iPhoneOS'],'MinimumOSVersion':'15.0' if fault=='minimum-os' else '16.0'}
                    cpu=0x0100000c if fault!='architecture' else 0x01000007
                    macho=struct.pack('<8I',0xfeedfacf,cpu,0,2,1,24,0,0)+struct.pack('<6I',0x32,24,2 if fault!='platform' else 7,0,0,0)
                    with zipfile.ZipFile(d/'Test.ipa','w') as z:
                        z.writestr('Payload/Test.app/Info.plist',plistlib.dumps(info))
                        z.writestr('Payload/Test.app/Test',macho)
                        z.writestr('Payload/Test.app/Web/index.html',b'actual-source' if fault!='asset' else b'tampered')
                    p=subprocess.run(['python3',str(ROOT/'scripts/verify_codemagic_ipa.py'),'--ipa',str(d/'Test.ipa'),'--app-name','Test','--bundle-id','app.test','--version','1.0','--build','1','--minimum-os','16.0','--source-sha','1'*40,'--web',str(d/'web'),'--output',str(d/'verification.json')],capture_output=True,text=True)
                    self.assertEqual(p.returncode==0,fault is None,p.stdout+p.stderr)
                    self.assertEqual((d/'verification.json').exists(),fault is None)
                    if fault is None:self.assertEqual(json.loads((d/'verification.json').read_text())['source_commit'],'1'*40)

if __name__=='__main__':unittest.main(verbosity=2)
