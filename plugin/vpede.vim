py3 <<EOF
import os
import sys

import vpe

pypath = vpe.script_py_path()
here = os.path.dirname(pypath)
if here not in sys.path:
    sys.path.append(here)

import vpede

vpede.run()
EOF

nnoremap <F3> :py3 vpede.quality_channel.send(QuitMessage())<cr>
