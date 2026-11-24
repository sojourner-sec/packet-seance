# Séance — Tech

## Stack
- Vanilla HTML, CSS and JavaScript only
- No frameworks, no bundler, no build step, no npm dependencies

## Audio
- Use the Web Audio API to synthesize all sound in code (oscillators, gain nodes, filters, noise)
- Sub-bass tension drone that rises, and a sharp discordant sting
- NO external audio files (no MP3, WAV or OGG)
- Create the AudioContext only after a user click, to satisfy browser autoplay rules
- A global mute toggle must silence everything

## Visuals
- CSS animations and transitions for the planchette, dimming, parchment mode and the inversion flash
- Victorian look: brass, aged parchment, candlelight, serif fonts
- Use system or web-safe fonts, or a Google Font with a safe fallback

## Code rules
- Plain, readable code with short comments
- Use ES6 features that work in current browsers
- Keep log analysis as pure functions that are easy to test
- Everything runs client-side; logs never leave the browser

## Deployment
- Must work when hosted as static files on GitHub Pages, Vercel or Netlify
- Use relative paths for all files