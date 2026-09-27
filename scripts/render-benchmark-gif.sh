#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_image="$repo_root/assets/benchmark-source-v2.png"
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
drawbox=x=24:y=18:w=912:h=504:color=0x020914@0.30:t=fill,
drawtext=fontfile=${font_file}:text='ONE STAGED LINE. TWO SCANNERS.':x=48:y=38:fontsize=18:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='Ready?':x=48:y=70:fontsize=34:fontcolor=white:alpha='if(lt(t,0.08),0,if(lt(t,1.18),1,0))',
drawtext=fontfile=${font_file}:text='Fast gate clear. Broad scan continues.':x=48:y=70:fontsize=30:fontcolor=white:alpha='if(between(t,1.82,4.84),1,0)',
drawtext=fontfile=${font_file}:text='Fast first. Comprehensive second.':x=48:y=70:fontsize=31:fontcolor=white:alpha='if(gte(t,4.84),1,0)',
drawtext=fontfile=${font_file}:text='secret-scanner':x=46:y=137:fontsize=22:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='FAST GATE':x=46:y=165:fontsize=14:fontcolor=0x79ffe1@0.82,
drawtext=fontfile=${font_file}:text='Gitleaks 8.25.1':x=46:y=319:fontsize=22:fontcolor=0xff9b6e,
drawtext=fontfile=${font_file}:text='BROAD GATE':x=46:y=347:fontsize=14:fontcolor=0xff9b6e@0.82,
drawtext=fontfile=${font_file}:text='[ +1 LINE ]':x='48+142*(1-pow(1-min(t/0.62,1),3))':y='245-3*sin(t*18)':fontsize=20:fontcolor=white:alpha='if(lt(t,0.76),1,0)',
drawtext=fontfile=${font_file}:text='STAGE':x=182:y=252:fontsize=13:fontcolor=0xb6c8da:alpha='if(between(t,0.76,1.18),1,0)',
drawtext=fontfile=${font_file}:text='●':x='if(lt(t,1.20),210-7*sin(max(t-0.76,0)*17),if(lt(t,1.68),210+669*(1-pow(1-(t-1.20)/0.48,3)),if(lt(t,1.90),879-9*(t-1.68)/0.22,870)))':y=153:fontsize=34:fontcolor=0x79ffe1,
drawtext=fontfile=${font_file}:text='•':x='if(lt(t,1.20),210,if(lt(t,1.68),180+669*(1-pow(1-(t-1.20)/0.48,3)),849))':y=159:fontsize=26:fontcolor=0x79ffe1@0.44:alpha='if(between(t,1.20,1.90),1,0)',
drawtext=fontfile=${font_file}:text='•':x='if(lt(t,1.20),210,if(lt(t,1.68),150+669*(1-pow(1-(t-1.20)/0.48,3)),819))':y=159:fontsize=22:fontcolor=0x79ffe1@0.22:alpha='if(between(t,1.20,1.90),1,0)',
drawtext=fontfile=${font_file}:text='○':x=854:y=140:fontsize=48:fontcolor=0x79ffe1:alpha='if(between(t,1.68,1.96),1-(t-1.68)/0.28,0)',
drawtext=fontfile=${font_file}:text='✓ 8 ms':x=760:y='126-8*exp(-4*max(t-1.72,0))*sin(15*max(t-1.72,0))':fontsize=23:fontcolor=0x79ffe1:alpha='if(gte(t,1.68),1,0)',
drawtext=fontfile=${font_file}:text='●':x='if(lt(t,1.20),210-7*sin(max(t-0.76,0)*17),210+660*(3*pow(min(max((t-1.20)/3.50,0),1),2)-2*pow(min(max((t-1.20)/3.50,0),1),3)))':y=333:fontsize=34:fontcolor=0xff9b6e,
drawtext=fontfile=${font_file}:text='•':x='if(lt(t,1.20),210,180+660*(3*pow(min(max((t-1.20)/3.50,0),1),2)-2*pow(min(max((t-1.20)/3.50,0),1),3)))':y=339:fontsize=26:fontcolor=0xff9b6e@0.40:alpha='if(between(t,1.20,4.90),1,0)',
drawtext=fontfile=${font_file}:text='•':x='if(lt(t,1.20),210,150+660*(3*pow(min(max((t-1.20)/3.50,0),1),2)-2*pow(min(max((t-1.20)/3.50,0),1),3)))':y=339:fontsize=22:fontcolor=0xff9b6e@0.20:alpha='if(between(t,1.20,4.90),1,0)',
drawtext=fontfile=${font_file}:text='○':x=854:y=320:fontsize=48:fontcolor=0xff9b6e:alpha='if(between(t,4.70,4.98),1-(t-4.70)/0.28,0)',
drawtext=fontfile=${font_file}:text='✓ 539 ms':x=732:y='306-8*exp(-4*max(t-4.74,0))*sin(15*max(t-4.74,0))':fontsize=23:fontcolor=0xff9b6e:alpha='if(gte(t,4.70),1,0)',
drawtext=fontfile=${font_file}:text='~67x faster on this patch':x=605:y=442:fontsize=25:fontcolor=0x79ffe1:alpha='if(gte(t,4.84),1,0)',
drawtext=fontfile=${font_file}:text='Same 224 B patch • measured medians • motion timing dramatized':x=48:y=488:fontsize=15:fontcolor=0xb6c8da,
fps=18"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/secret-scanner-gif.XXXXXX")
trap 'find "$temporary" -depth -delete' EXIT

ffmpeg -hide_banner -loglevel error -y \
    -loop 1 -t 6.5 -i "$source_image" \
    -vf "$filter" "$temporary/frame-%03d.png"

ffmpeg -hide_banner -loglevel error -y \
    -framerate 18 -i "$temporary/frame-%03d.png" \
    -vf "palettegen=max_colors=128:stats_mode=diff" \
    -frames:v 1 "$temporary/palette.png"

ffmpeg -hide_banner -loglevel error -y \
    -framerate 18 -i "$temporary/frame-%03d.png" \
    -i "$temporary/palette.png" \
    -lavfi "[0:v][1:v]paletteuse=dither=bayer:bayer_scale=4" \
    -loop 0 "$output"

printf 'wrote %s\n' "$output"
