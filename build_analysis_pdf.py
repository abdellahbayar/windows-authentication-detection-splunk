"""Create the portfolio analysis report from the verified synthetic fixtures."""
import html
import json
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Table, TableStyle
from reportlab.lib import colors
from PIL import Image as PILImage
from build_pdf import ROOT, WORKSPACE, styles, decorate
from portfolio_cover import draw_portfolio_cover

OUTPUT=WORKSPACE/'output/pdf/Windows-Authentication-Splunk-Analysis-Abdellah-Bayar.pdf'
CONTENTS=[('Scope, dataset and technologies',2),('Event fields and correlation keys',3),
          ('Rolling-window detection logic',4),('Expected findings and scenario controls',5),
          ('Offline validation and Splunk execution',6),('Investigation and evidence limits',7),('Sources and evidence map',8)]

def image(name):
    path=ROOT/'screenshots'/name
    with PILImage.open(path) as im:w,h=im.size
    scale=min(519/w,275/h)
    return Image(str(path),width=w*scale,height=h*scale)

def cover(c,d):
    draw_portfolio_cover(c,CONTENTS,second='Synthetic-data detection analysis and expected results')

def build():
    manifest=json.loads((ROOT/'data/manifest.json').read_text())
    verification=json.loads((ROOT/'verification.json').read_text())
    assert manifest['events']==55 and verification['status']=='PASS'
    chapters=[
        ('Scope, dataset and technologies',[
            'The project defines an authentication detection exercise using Splunk searches and a generated Windows-like event dataset. It extends the earlier local Windows authentication investigation with a reproducible rule, dashboard and scheduled-alert configuration.',
            'The historical fixture contains 55 records: 46 failed logons and nine successes across ten controlled scenarios. Lab names include DESKTOP-N7PEBGK, LabUser, LabAdmin and soc-mail-lab. WIN-LAB-02 is an invented control host.',
            'Deliverables include JSONL/CSV data, eight SPL searches, an installable Splunk app, a Simple XML dashboard, a disabled scheduled alert and reproduction instructions. The record format is normalized JSON rather than an EVTX or native Windows XML export.',
            'Verification status: the dataset, Python reference implementation, configuration structure and interactive preview have been checked offline. Execution of the SPL searches, dashboard and alert in Splunk remains pending.'
        ],'architecture.png'),
        ('Event fields and correlation keys',[
            'EventCode 4625 represents a failed authentication and 4624 a successful logon session. TargetUserName identifies the authentication target; SubjectUserName identifies the requester. Using the requester as the target would join the wrong identities.',
            'The rule correlates run_id, Computer, TargetDomainName, TargetUserName, SourceIp and LogonType. Account and domain names are normalized to lower case. Record identity uses run_id, Computer and EventRecordID for deduplication.',
            'SubStatus 0xC000006A represents an incorrect password in the fixture. 0xC0000064 represents an unknown username. LogonType 2 is interactive and 3 network. SourceIp is the project name for the normalized Windows IpAddress field.',
            'The fixture uses ::1 for local test activity. The address of the Ubuntu Splunk server is unrelated to the authentication source. Missing correlation fields must be investigated rather than filled with invented values.'
        ],'events.png'),
        ('Rolling-window detection logic',[
            'For each successful event, the search counts failures in the preceding five minutes for the same correlation key. The threshold is at least five failures. Events are deduplicated and sorted chronologically before streamstats calculates the window.',
            'current=f excludes the current event from the running calculation. The success must follow the relevant failures; an earlier success does not establish a failed-then-success sequence. The full query is provided in queries/03-detection.spl.',
            'scenario_id labels test data for comparison but is not a condition of the detection. Fixed five-minute buckets are avoided because a sequence can cross a bucket boundary.',
            'This small-data design uses sort 0. Production deployment requires separate performance testing, delay handling, threshold tuning and detection coverage assessment.'
        ],'detection.png'),
        ('Expected findings and scenario controls',[
            'The reference result contains two candidates. S01 has five failures followed by a success at 09:01:40 UTC, 100 seconds after the first failure. S08 has five failures followed by success at 10:49:40 UTC over 280 seconds. Both use LabUser, DESKTOP-N7PEBGK, ::1 and LogonType 2.',
            'Eight negative cases check a single mistyped password, a success before the failures, another target account, failures outside the window, another source address, another logon type, an unknown username without a success, and another computer.',
            'Expected result IDs and counts are in data/expected-detections.csv and report/test-matrix.csv. These files contain reference output, not results exported from Splunk.',
            'The two matching patterns are intentionally present in generated data. They are candidates for investigation and do not demonstrate credential theft or compromise.'
        ],'dashboard.png'),
        ('Offline validation and Splunk execution',[
            'Offline checks passed for all ten scenarios. Additional checks cover duplicate records, a four-failure sequence, account-name case, a missing source field, a changed target domain and XML/configuration structure. The live-fixture generator also produces a valid six-event synthetic test.',
            'Preview checks passed for filtering, CSV download and mobile layout. Screenshots of that preview are illustrative figures. Original Ubuntu terminal captures document the VM prerequisites only.',
            'To validate in Splunk, install the app, search over All time, confirm 55 events and compare both detection IDs with expected output. Then enable the live alert, generate a current-time fixture and record the scheduled job and Triggered Alerts result.',
            'The alert runs each minute with a one-minute event-time delay and suppresses repeated detection IDs for ten minutes. The schedule assumes limited ingestion delay and must be adjusted for late-arriving real telemetry. No external notification or containment action is configured.'
        ],'validation.png'),
        ('Investigation and evidence limits',[
            'Observed in the fixture: five errors precede one accepted authentication for the same key. Possible explanations in real telemetry include repeated manual mistakes, administrative tests or unauthorized attempts. The logon result alone does not identify the person or intent.',
            'Follow-up checks should confirm the operator and test context, preserve original events, inspect process and session details, review post-logon activity, search other accounts or hosts and assess audit completeness.',
            'Strict source and logon-type correlation can miss activity that changes either key. Missing fields are excluded. Repeated successes can create separate candidates. Exact boundary behavior at 300 seconds is a separate Splunk check.',
            'This project does not assert a production incident, EDR response or completed Splunk runtime validation. The optional export script reads selected lab-account events without creating users, changing audit policy or generating authentication attempts.'
        ],'triage.png'),
        ('Sources and evidence map',[
            'data/authentication.jsonl: generated historical records, run lab-auth-20261008. data/manifest.json: record totals and known-outcome scenarios. data/expected-detections.csv: expected candidates from the reference implementation.',
            'queries/: copyable searches. app/abdellah_auth_lab/: parsing, input, index, saved searches and dashboard. verification.json and preview/verification.json: offline test results. report/actual-validation-template.md: future runtime evidence record.',
            'screenshots/: original Ubuntu prerequisites and clearly labeled illustrative previews. evidence/actual-splunk/ is reserved for captures and exports from the actual Splunk instance.',
        ],None),
    ]
    story=[Spacer(1,10),PageBreak()]
    sources=json.loads((ROOT/'guide-content.json').read_text())[-1]['links']
    for i,(title,paras,screen) in enumerate(chapters):
        if i:story.append(PageBreak())
        story.append(Paragraph('SECURITY LABS / 04',styles['tag']))
        story.append(Paragraph(f'{i+1:02d} / {html.escape(title)}',styles['title']))
        for p in paras:story.append(Paragraph(html.escape(p),styles['body']))
        if screen:
            story.append(image(screen))
            story.append(Paragraph('Illustrative preview of expected results using the synthetic dataset.',styles['caption']))
        if i==6:
            for title,url in sources:
                story.append(Paragraph(f'<a href="{html.escape(url,quote=True)}" color="#17649c">{html.escape(title)}</a>',styles['body']))
    doc=SimpleDocTemplate(str(OUTPUT),pagesize=A4,leftMargin=38,rightMargin=38,topMargin=57,bottomMargin=53,
                          title='Windows Authentication Detection with Splunk - Analysis',author='Abdellah Bayar')
    doc.build(story,onFirstPage=cover,onLaterPages=decorate)
    from pypdf import PdfReader
    reader=PdfReader(str(OUTPUT));assert len(reader.pages)==8,len(reader.pages)
    print(json.dumps({'analysis_pdf':str(OUTPUT),'pages':len(reader.pages)}))

if __name__=='__main__':build()
