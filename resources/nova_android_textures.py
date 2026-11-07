"""Native ports of NovaTexturePatterns.kt. No approximate automatic replacements."""

import nova_native_render

TEXTURE_IDS = ('none', 'basalt', 'marble', 'wood', 'sand', 'grass', 'cracks', 'water',
               'smoke', 'starfield', 'slime', 'shards', 'splatter', 'lightning', 'snow', 'fractal', 'matrix')


def render_mask(texture, width, height, variant):
    if (texture not in TEXTURE_IDS or not 8 <= width <= 1440 or not 8 <= height <= 1440
            or not 0 <= variant <= 2147483647):
        raise ValueError('Invalid Android texture parameters')
    pixels = nova_native_render.texture_mask(texture, width, height, variant)
    if pixels is None:
        reason = nova_native_render._disabled_reason or 'нативный расчёт выключен'
        raise RuntimeError(f'Генератор фактур Android недоступен: {reason}. Обновите nova-engine.exe.')
    return pixels


def render_matrix(width, height, variant, time, source, crop, alpha_scale):
    pixels = nova_native_render.matrix_rain(width, height, variant, time, source, crop, alpha_scale)
    if pixels is None:
        reason = nova_native_render._disabled_reason or 'нативный расчёт выключен'
        raise RuntimeError(f'Генератор Matrix Android недоступен: {reason}. Обновите nova-engine.exe.')
    return pixels
