"""Regenerate independent fixtures from the original, unmodified Android sources.

Requires Java and Kotlin 2.2.10 compiler/stdlib jars in the local Gradle cache.
Run: python tests/android_reference/regenerate.py --android-source "../Nova Android/app/src/main/java/com/example/nova"
No native renderer is invoked while generating expected results.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def canonical(value):
    if isinstance(value, float):
        return struct.pack('<f', 0.0 if value == 0 else value).hex()
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    return value


def event_hash(events):
    data = json.dumps(canonical(events), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(data.encode()).hexdigest()


def generate(source, cache, destination):
    here = Path(__file__).resolve().parent
    stdlib = next((cache / 'org.jetbrains.kotlin/kotlin-stdlib/2.2.10').rglob('*.jar'))
    compiler = next((cache / 'org.jetbrains.kotlin/kotlin-compiler-embeddable/2.2.10').rglob('*.jar'))
    jars = [compiler, stdlib]
    for name in ('org.jetbrains.kotlin/kotlin-script-runtime/2.2.10', 'org.jetbrains.kotlin/kotlin-reflect',
                 'org.jetbrains.kotlin/kotlin-daemon-embeddable/2.2.10',
                 'org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm',
                 'org.jetbrains.intellij.deps/trove4j', 'org.jetbrains/annotations'):
        jars.extend((cache / name).rglob('*.jar'))
    flags = dict(capture_output=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    def run(command):
        result = subprocess.run(command, timeout=120, **flags)
        if result.returncode:
            raise RuntimeError(result.stderr.decode('utf-8', errors='replace')[-5000:])

    names = ('basalt', 'marble', 'wood', 'sand', 'grass', 'cracks', 'water', 'smoke',
             'starfield', 'slime', 'shards', 'splatter', 'lightning', 'snow', 'fractal', 'matrix')
    sources = ('NovaTexturePatterns.kt', 'NovaMatrixRain.kt')
    fixture = {
        'reference': 'Unmodified Nova Android Kotlin 2.2.10/JVM sources with an alpha-field and Canvas-command sink. Vector raster antialiasing is platform-specific.',
        'sources_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in sources},
        'cases': [], 'rain_cases': [],
    }
    with tempfile.TemporaryDirectory(prefix='nova-android-reference-') as temporary:
        work = Path(temporary)
        jar = work / 'reference.jar'
        run(['java', '-Xmx512m', '-cp', os.pathsep.join(map(str, jars)),
             'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
             '-classpath', str(stdlib), '-d', str(jar),
             *(str(here / name) for name in ('Graphics.kt', 'AndroidFullReference.kt', 'AndroidRainReference.kt')),
             *(str(source / name) for name in sources)])
        java = ['java', '-Xmx256m', '-cp', os.pathsep.join((str(jar), str(stdlib)))]
        for texture in names:
            for variant, width, height in ((0, 80, 60), (197, 60, 80)):
                output = work / 'texture'
                run([*java, 'com.example.nova.AndroidFullReferenceKt', texture,
                     str(width), str(height), str(variant), str(output)])
                pixels = output.with_suffix('.pgm').read_bytes().split(b'\n', 3)[3]
                events = json.loads(output.with_suffix('.json').read_text(encoding='utf-8'))
                fixture['cases'].append(dict(texture=texture, width=width, height=height, variant=variant,
                    base_sha256=hashlib.sha256(pixels).hexdigest(), events_sha256=event_hash(events),
                    event_count=len(events)))
        for variant, width, height in ((0, 80, 60), (197, 60, 80)):
            for time, alpha in ((0, 1), (7.5, .18), (65, .6), (3600, 1), (86400, .18)):
                output = work / 'rain.json'
                run([*java, 'com.example.nova.AndroidRainReferenceKt', str(width), str(height),
                     str(variant), str(time), str(alpha), str(output)])
                events = json.loads(output.read_text(encoding='utf-8'))
                fixture['rain_cases'].append(dict(width=width, height=height, variant=variant, time=time,
                    alpha_scale=alpha, event_count=len(events), events_sha256=event_hash(events)))
    destination.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android-source', type=Path, required=True)
    parser.add_argument('--gradle-cache', type=Path, default=Path.home() / '.gradle/caches/modules-2/files-2.1')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'fixtures/android_textures.json')
    args = parser.parse_args()
    generate(args.android_source.resolve(), args.gradle_cache, args.output)
