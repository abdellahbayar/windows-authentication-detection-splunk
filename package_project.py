"""Package the complete lab and verify provenance, generated live data and archive integrity."""
import hashlib
import json
import shutil
import tarfile
import uuid
import zipfile
from pathlib import Path
from generate_data import write_live, detect_reference

ROOT=Path(__file__).resolve().parent
WORKSPACE=ROOT.parents[2]

def main():
    pdf=WORKSPACE/'output/pdf/Windows-Authentication-Detection-with-Splunk.pdf'
    docs=ROOT/'docs';docs.mkdir(exist_ok=True)
    shutil.copy2(pdf,docs/pdf.name)
    analysis=WORKSPACE/'output/pdf/Windows-Authentication-Splunk-Analysis-Abdellah-Bayar.pdf'
    shutil.copy2(analysis,docs/analysis.name)
    old_copy=ROOT/pdf.name
    if old_copy.exists(): old_copy.unlink()
    shots=[{'file':p.name,'kind':'original_lab_preparation_capture' if 'real' in p.name else 'illustrative_local_preview',
            'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted((ROOT/'screenshots').glob('*.png'))]
    (ROOT/'screenshots/provenance.json').write_text(json.dumps(shots,indent=2))
    qa=WORKSPACE/'tmp/splunk-verification'; qa.mkdir(parents=True,exist_ok=True)
    live=qa/('live-'+uuid.uuid4().hex+'.jsonl')
    write_live(live)
    events=[json.loads(x) for x in live.read_text().splitlines()]
    assert len(events)==6 and all(e['synthetic'] for e in events)
    assert [e['EventCode'] for e in events]==[4625]*5+[4624]
    assert len(detect_reference(events))==1
    with tarfile.open(ROOT/'abdellah_auth_lab.tar.gz','r:gz') as archive:
        assert all(m.name=='abdellah_auth_lab' or m.name.startswith('abdellah_auth_lab/') for m in archive.getmembers())
        assert not any(m.issym() or m.islnk() for m in archive.getmembers())
    preview=json.loads((ROOT/'preview/verification.json').read_text())
    assert not preview['pageErrors'] and not preview['mobileOverflow']
    files=[p for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts
           and p.suffix!='.pyc' and p.name not in ('export-check.csv','SHA256SUMS.json')]
    manifest={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (ROOT/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2))
    output=WORKSPACE/'output/Windows-Authentication-Splunk-Complete-Project.zip'
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
        for p in files+[ROOT/'SHA256SUMS.json']:
            z.write(p,'windows-authentication-splunk/'+p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(output) as z:
        assert z.testzip() is None and len(z.namelist())==len(set(z.namelist()))
        for name,sha in manifest.items(): assert hashlib.sha256(z.read('windows-authentication-splunk/'+name)).hexdigest()==sha
        print(json.dumps({'zip':str(output),'files':len(z.namelist()),'screenshots':len(shots),
                          'bytes':output.stat().st_size,'checks':'offline reference/static, live generator, preview UI, provenance and archives PASS',
                          'splunk_runtime_verified':False},indent=2))

if __name__=='__main__': main()
