import json,sys,os
OUT=os.environ.get('OUT','testrun')
T=json.load(open(OUT+'/ground_truth.json'))
truth=T['truth']; tfiles={t['file'] for t in truth}
hard={t['file'] for t in truth if t.get('hard')}
hist={t['file'] for t in truth if t['where']!='HEAD'}
def files_ds(): d=json.load(open(OUT+'/ds.json')); return {f for f,v in d['results'].items() if v}
def files_th(fn): return {x['path'] for x in json.load(open(fn))}
def files_fb(): return {x['file'] for x in json.load(open(OUT+'/fallback.json'))}
tools={'fallback scanner (skill)':files_fb(),'detect-secrets (tree only)':files_ds(),
 'trufflehog3 rules-only (history)':files_th('testrun/th3_rules.json'),
 'trufflehog3 +entropy (history)':files_th('testrun/th3_entropy.json')}
tools['all three layered']=tools['fallback scanner (skill)']|tools['detect-secrets (tree only)']|tools['trufflehog3 rules-only (history)']
rows=[]
for n,f in tools.items():
    tp=f&tfiles; fp=f-tfiles
    rows.append({'tool':n,'files_flagged':len(f),'true_files_found':f"{len(tp)}/{len(tfiles)}",
      'recall':round(len(tp)/len(tfiles),2),'precision':round(len(tp)/len(f),2) if f else None,
      'history_only_found':f"{len(f&hist)}/{len(hist)}",'hard_cases_found':f"{len(f&hard)}/{len(hard)}",
      'false_positive_files':sorted(fp),'missed':sorted(tfiles-f)})
json.dump(rows,open(OUT+'/results.json','w'),indent=2)
for r in rows: print(json.dumps(r))
print('truth files',len(tfiles),'items',len(truth),'history-only/branch-only files',sorted(hist),'hard',sorted(hard))
