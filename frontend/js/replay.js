// Incident Replay & Forensic Time-Travel Controller
export class ReplayController {
  constructor(sliderId, onTimeTravel) {
    this.slider = document.getElementById(sliderId);
    this.onTimeTravel = onTimeTravel;
    this.timestamps = [];
    this.currentIndex = 0;
    this.isPlaying = false;
    this.playInterval = null;

    if (this.slider) {
      this.slider.addEventListener('input', (e) => {
        const idx = parseInt(e.target.value, 10);
        this.jumpToIndex(idx);
      });
    }

    const btnPlay = document.getElementById('btn-replay-play');
    const btnPrev = document.getElementById('btn-replay-prev');
    const btnNext = document.getElementById('btn-replay-next');

    if (btnPlay) {
      btnPlay.addEventListener('click', () => this.togglePlay());
    }
    if (btnPrev) {
      btnPrev.addEventListener('click', () => this.step(-1));
    }
    if (btnNext) {
      btnNext.addEventListener('click', () => this.step(1));
    }
  }

  setTimestamps(timestamps) {
    this.timestamps = timestamps || [];
    if (this.slider) {
      this.slider.min = 0;
      this.slider.max = Math.max(0, this.timestamps.length - 1);
      this.slider.value = this.timestamps.length - 1;
      this.currentIndex = Math.max(0, this.timestamps.length - 1);
    }
    this.updateLabels();
  }

  jumpToIndex(idx) {
    if (idx < 0 || idx >= this.timestamps.length) return;
    this.currentIndex = idx;
    if (this.slider) this.slider.value = idx;
    this.updateLabels();
    if (this.onTimeTravel) {
      this.onTimeTravel(this.timestamps[idx]);
    }
  }

  step(delta) {
    const next = this.currentIndex + delta;
    if (next >= 0 && next < this.timestamps.length) {
      this.jumpToIndex(next);
    }
  }

  togglePlay() {
    this.isPlaying = !this.isPlaying;
    const btn = document.getElementById('btn-replay-play');
    if (btn) {
      btn.innerText = this.isPlaying ? '❚❚ Pause' : '▶ Play';
    }

    if (this.isPlaying) {
      if (this.currentIndex >= this.timestamps.length - 1) {
        this.currentIndex = 0;
      }
      this.playInterval = setInterval(() => {
        if (this.currentIndex < this.timestamps.length - 1) {
          this.step(1);
        } else {
          this.togglePlay();
        }
      }, 1500);
    } else {
      if (this.playInterval) clearInterval(this.playInterval);
    }
  }

  updateLabels() {
    const lblCurrent = document.getElementById('lbl-replay-current');
    const lblStart = document.getElementById('lbl-replay-start');
    const lblEnd = document.getElementById('lbl-replay-end');

    if (this.timestamps.length > 0) {
      const cur = new Date(this.timestamps[this.currentIndex]).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
      const start = new Date(this.timestamps[0]).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
      const end = new Date(this.timestamps[this.timestamps.length - 1]).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });

      if (lblCurrent) lblCurrent.innerText = `Replay Cursor: ${cur} (${this.currentIndex + 1}/${this.timestamps.length})`;
      if (lblStart) lblStart.innerText = start;
      if (lblEnd) lblEnd.innerText = end;
    }
  }
}
