from pathlib import Path
import shutil
root=Path(__file__).resolve().parents[1]
def bundled_module(name):
    source='\n'.join(line for line in (root/'web'/name).read_text().splitlines() if not line.startswith('import '))
    return source.replace('export async function ', 'async function ').replace('export function ', 'function ').replace('export const ', 'const ')
core='\n'.join(bundled_module(name) for name in ['core.mjs','discovery.mjs','evidence.mjs','har.mjs'])
app='\n'.join(line for line in (root/'web/app.mjs').read_text().splitlines() if not line.startswith('import '))
(root/'web/bundle.js').write_text("'use strict';\n(()=>{\n"+core+'\n'+app+'\n})();\n')
for target in [root/'android/app/src/main/assets/web',root/'ios/ScopePilot/Web']:
    target.mkdir(parents=True,exist_ok=True)
    for name in ['index.html','style.css','bundle.js']:
        shutil.copyfile(root/'web'/name,target/name)
print('Synced first-party assets to Android and iOS.')

