#!/usr/bin/env python3
"""Generates a 75-second warm ambient electronic WAV soundtrack (44.1 kHz stereo)
using only the Python standard library (`math`, `struct`, `wave`)."""

import math
import struct
import wave

SAMPLE_RATE = 44100
DURATION_SEC = 75
NUM_SAMPLES = SAMPLE_RATE * DURATION_SEC

# Warm ambient progression in D minor / F major (Dm9 -> Bbmaj7 -> Fmaj7 -> Csus4)
CHORDS = [
    [146.83, 220.00, 261.63, 329.63, 349.23],  # Dm9
    [116.54, 174.61, 220.00, 293.66, 349.23],  # Bbmaj7
    [174.61, 220.00, 261.63, 329.63, 392.00],  # Fmaj9
    [130.81, 196.00, 261.63, 293.66, 392.00],  # Csus2
]
ARP_NOTES = [293.66, 349.23, 440.00, 523.25, 659.25, 523.25, 440.00, 349.23]


def main(out_path: str = "bgm.wav") -> None:
    frames = bytearray()
    chord_len = 5.0  # seconds per chord
    arp_step = 0.3125  # 96 BPM sixteenth/eighth pulse

    for i in range(NUM_SAMPLES):
        t = i / SAMPLE_RATE
        # Global fade in (2s) and fade out (3s)
        env = 1.0
        if t < 2.0:
            env = t / 2.0
        elif t > DURATION_SEC - 3.0:
            env = max(0.0, (DURATION_SEC - t) / 3.0)

        c_idx = int(t / chord_len) % len(CHORDS)
        c_pos = (t % chord_len) / chord_len
        pad_env = math.sin(math.pi * min(1.0, c_pos * 1.15)) ** 0.45

        # Soft detuned pad
        left = 0.0
        right = 0.0
        for j, freq in enumerate(CHORDS[c_idx]):
            w1 = math.sin(2.0 * math.pi * freq * t)
            w2 = math.sin(2.0 * math.pi * (freq * 1.003) * t + j * 0.7)
            w3 = 0.25 * math.sin(2.0 * math.pi * (freq * 2.0) * t)
            sig = (w1 + 0.6 * w2 + w3) * 0.08 * pad_env
            pan = 0.35 + 0.3 * ((j % 3) / 2.0)
            left += sig * (1.0 - pan)
            right += sig * pan

        # Subtle sub-bass pulse
        bass_f = CHORDS[c_idx][0] * 0.5
        bass_pulse = 0.5 + 0.5 * math.sin(2.0 * math.pi * 0.8 * t)
        bass = math.sin(2.0 * math.pi * bass_f * t) * 0.14 * bass_pulse
        left += bass
        right += bass

        # Gentle plucked glass arpeggio (enters at t=8s, fades at t=70s)
        if 8.0 <= t <= 70.0:
            step_idx = int(t / arp_step)
            local_t = t - step_idx * arp_step
            pluck_env = math.exp(-local_t * 9.5)
            af = ARP_NOTES[step_idx % len(ARP_NOTES)]
            if c_idx == 1:
                af *= 0.8909  # gentle harmonic shift on Bbmaj7
            pluck = (
                math.sin(2.0 * math.pi * af * t)
                + 0.3 * math.sin(2.0 * math.pi * af * 2.0 * t)
            ) * 0.075 * pluck_env
            arp_pan = 0.5 + 0.35 * math.sin(step_idx * 0.9)
            left += pluck * (1.0 - arp_pan)
            right += pluck * arp_pan

        l_s16 = max(-32767, min(32767, int(left * env * 28000)))
        r_s16 = max(-32767, min(32767, int(right * env * 28000)))
        frames.extend(struct.pack("<hh", l_s16, r_s16))

    with wave.open(out_path, "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(frames)
    print(f"Generated {out_path} ({DURATION_SEC}s, 44.1kHz stereo)")


if __name__ == "__main__":
    main()
