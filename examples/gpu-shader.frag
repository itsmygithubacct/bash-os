// GLES2 fragment shader. uv has its origin at the top left.
precision mediump float;
varying vec2 uv;
uniform vec2 resolution;
uniform float time;
uniform sampler2D canvas;

void main() {
    vec2 p = (uv - 0.5) * vec2(resolution.x / resolution.y, 1.0);
    float rings = sin(24.0 * length(p) - 2.0 * time);
    float wave = sin(7.0 * p.x + 3.0 * p.y + time);
    vec3 ink = 0.5 + 0.5 * cos(vec3(0.0, 2.0, 4.0) + rings + wave + time * 0.25);
    vec3 label = texture2D(canvas, uv).rgb;
    gl_FragColor = vec4(max(ink * (0.4 + 0.6 * (1.0 - smoothstep(0.0, 1.0, length(p)))), label), 1.0);
}
