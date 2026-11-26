# Cowrie 75-Second Motion Graphics Demo (`demo-video/`)

A zero-dependency **HTML5 Canvas 2D + WebAudio** motion-graphics studio (imperative frame timeline — no React/Remotion re-render overhead), with synchronized subtitles and procedural ambient music.

> **Tip (Alternative Framework):** If you later want a full TypeScript timeline editor with node-based animations, [Motion Canvas](https://motioncanvas.io) (`@motion-canvas/core` + `@motion-canvas/2d`) is the leading imperative coroutine-based improvement over React Motion / Remotion.

## Export a 1080p MP4 in 2 Steps

1. Open `demo-video/index.html` in Google Chrome and click **● Export 1080p WebM + Music** (downloads `cowrie-demo.webm` with 60fps 1080p visuals, burned-in subtitles, and WebAudio ambient soundtrack).
2. Convert to H.264 MP4 for Devpost / YouTube / X:
   ```bash
   ffmpeg -y -i ~/Downloads/cowrie-demo.webm \
     -c:v libx264 -pix_fmt yuv420p -crf 18 -c:a aac -b:a 192k \
     demo-video/cowrie-demo.mp4
   ```

## Standalone Audio & Subtitles
- Generate a standalone 75s stereo ambient soundtrack (`bgm.wav`):
  ```bash
  python3 demo-video/generate_music.py
  ```
- Soft-subtitle track for YouTube / Vimeo: `demo-video/subtitles.srt`.
