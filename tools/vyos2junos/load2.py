import os, json, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bfmeasure import measure, session, RESULTS, WORK
log=[]; bf=session(sys.argv[1]); out={}
for name in sys.argv[2:]:
    with measure(f"init {name}", log):
        bf.init_snapshot(f"{WORK}/snap/{name}", name=name, overwrite=True)
    bf.set_snapshot(name)
    fps=bf.q.fileParseStatus().answer().frame(); iss=bf.q.initIssues().answer().frame(); pw=bf.q.parseWarning().answer().frame()
    ur=bf.q.undefinedReferences().answer().frame()
    out[name]={"status":fps["Status"].value_counts().to_dict(),"initIssues":iss["Type"].value_counts().to_dict() if len(iss) else {},
               "issue_examples":[str(x)[:200] for x in iss["Details"].head(5)] if len(iss) else [],
               "parseWarnings":len(pw),"pw_examples":[str(x)[:160] for x in pw["Text"].head(5)] if len(pw) else [],"undefinedRefs":len(ur)}
    print(name, json.dumps(out[name]), flush=True)
json.dump({"load":out,"timings":log},open(f"{RESULTS}/load2-{'_'.join(sys.argv[2:])}.json","w"),indent=1,default=str)
