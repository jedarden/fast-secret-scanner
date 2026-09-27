#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_image="$repo_root/assets/benchmark-source.png"
output="$repo_root/assets/benchmark.gif"

if ! command -v ffmpeg >/dev/null; then
    echo "ffmpeg is required" >&2
    exit 2
fi

font_file=${FONT_FILE:-}
if [[ -z "$font_file" ]] && command -v fc-match >/dev/null; then
    font_file=$(fc-match -f '%{file}' 'DejaVu Sans' | head -1)
fi
if [[ -z "$font_file" || ! -f "$font_file" ]]; then
    echo "set FONT_FILE to a readable sans-serif TrueType font" >&2
    exit 2
fi

filter="scale=960:540:force_original_aspect_ratio=increase,crop=960:540,
drawbox=x=24:y=20:w=912:h=500:color=0x020914@0.42:t=fill,
drawtext=fontfile=${font_file}:text='STAGED SECRET SCAN':x=52:y=44:fontsize=20:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='Fast feedback. Broad backup.':x=52:y=76:fontsize=34:fontcolor=white,
drawtext=fontfile=${font_file}:text='secret-scanner':x=54:y=152:fontsize=24:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='8 ms median':x=54:y=184:fontsize=18:fontcolor=white:alpha='if(gte(t,0.70),1,0)',
drawtext=fontfile=${font_file}:text='●':x='230+min(t/0.70,1)*620':y=214:fontsize=36:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='Gitleaks 8.25.1':x=54:y=334:fontsize=24:fontcolor=0xff9b6e,
drawtext=fontfile=${font_file}:text='539 ms median':x=54:y=366:fontsize=18:fontcolor=white:alpha='if(gte(t,3.40),1,0)',
drawtext=fontfile=${font_file}:text='●':x='230+min(t/3.40,1)*620':y=396:fontsize=36:fontcolor=0xff9b6e,
drawtext=fontfile=${font_file}:text='~67x faster':x=706:y=70:fontsize=28:fontcolor=0x79ffe1:alpha='if(gte(t,3.40),1,0)',
drawtext=fontfile=${font_file}:text='1 added line • same 224 B patch • medians':x=52:y=486:fontsize=17:fontcolor=0xb6c8da,
fps=15,split[frames][palette];[palette]palettegen=max_colors=128:stats_mode=diff[p];[frames][p]paletteuse=dither=bayer:bayer_scale=4"

ffmpeg -hide_banner -loglevel error -y \
    -loop 1 -t 5 -i "$source_image" \
    -filter_complex "$filter" \
    -loop 0 "$output"

printf 'wrote %s\n' "$output"
