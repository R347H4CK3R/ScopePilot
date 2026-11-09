from pathlib import Path
import shutil
root=Path(__file__).resolve().parents[1]
core=(root/'web/core.mjs').read_text().replace('export function ', 'function ')
app='\n'.join((root/'web/app.mjs').read_text().splitlines()[1:])
(root/'web/bundle.js').write_text("'use strict';\n(()=>{\n"+core+'\n'+app+'\n})();\n')
for target in [root/'android/app/src/main/assets/web',root/'ios/ScopePilot/Web']:
    target.mkdir(parents=True,exist_ok=True)
    for name in ['index.html','style.css','bundle.js']:
        shutil.copyfile(root/'web'/name,target/name)
print('Synced first-party assets to Android and iOS.')
