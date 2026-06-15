/**
 * Toast notification system
 * Can be used from any JavaScript context
 */

export type ToastType = 'success' | 'error' | 'info' | 'warning';

interface ToastOptions {
  duration?: number;
  id?: string;
  onClick?: () => void;
  clickLabel?: string;
}

/**
 * Map raw API error strings to user-friendly messages
 */
export function friendlyError(msg: string): string {
  if (msg?.includes('API_KEY')) {
    return 'AI provider not configured — set your API key in settings';
  }
  if (msg === 'invalid body') {
    return 'Invalid request format — please try again';
  }
  if (msg === 'enabled required') {
    return 'Missing required field — please try again';
  }
  return msg;
}

/**
 * Show a toast notification
 */
export function toast(
  message: string,
  type: ToastType = 'info',
  options: ToastOptions = {}
) {
  const {
    duration = type === 'error' ? 8000 : 5000,
    id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    onClick,
    clickLabel,
  } = options;

  // Create container if it doesn't exist
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2';
    document.body.appendChild(container);
  }

  // Create toast element
  const toastEl = document.createElement('div');
  toastEl.id = id;
  toastEl.className = `toast fixed bottom-4 right-4 flex items-center gap-3 border rounded-lg px-4 py-3 max-w-sm animate-slide-in ${getColors(
    type
  ).bg}`;
  toastEl.setAttribute('role', 'alert');
  toastEl.setAttribute('data-type', type);

  // Icon
  const icon = document.createElement('span');
  icon.className = `material-symbols-outlined ms-fill text-xl ${getColors(type).text}`;
  icon.textContent = getIcon(type);

  // Message
  const messageEl = document.createElement('span');
  messageEl.className = `text-sm ${getColors(type).text}`;
  messageEl.textContent = message;

  toastEl.appendChild(icon);
  toastEl.appendChild(messageEl);

  // Action button (if onClick provided)
  if (onClick && clickLabel) {
    const actionBtn = document.createElement('button');
    actionBtn.className = 'text-xs font-bold text-blue-400 hover:text-blue-300 transition-colors underline';
    actionBtn.textContent = clickLabel;
    actionBtn.onclick = (e) => {
      e.stopPropagation();
      removeToast(toastEl);
      onClick();
    };
    toastEl.appendChild(actionBtn);
  }

  // Close button
  const closeBtn = document.createElement('button');
  closeBtn.className = 'ml-auto text-slate-400 hover:text-slate-300 transition-colors';
  closeBtn.setAttribute('aria-label', 'Close notification');
  closeBtn.innerHTML = '<span class="material-symbols-outlined ms-fill">close</span>';
  closeBtn.onclick = () => removeToast(toastEl);

  toastEl.appendChild(closeBtn);
  container.appendChild(toastEl);

  // Make entire toast clickable if onClick provided
  if (onClick) {
    toastEl.style.cursor = 'pointer';
    toastEl.onclick = (e) => {
      if ((e.target as HTMLElement).closest('button')) return;
      removeToast(toastEl);
      onClick();
    };
  }

  // Auto-dismiss
  if (duration > 0) {
    const timeoutId = setTimeout(() => removeToast(toastEl), duration);
    toastEl.onmouseenter = () => clearTimeout(timeoutId);
    toastEl.onmouseleave = () =>
      setTimeout(() => removeToast(toastEl), duration);
  }

  return id;
}

function removeToast(el: HTMLElement) {
  el.style.animation = 'slide-out 300ms ease-out forwards';
  setTimeout(() => el.remove(), 300);
}

function getColors(type: ToastType) {
  const colors = {
    success: {
      bg: 'bg-green-500/10 border-green-500/20',
      text: 'text-green-400',
    },
    error: {
      bg: 'bg-red-500/10 border-red-500/20',
      text: 'text-red-400',
    },
    info: {
      bg: 'bg-blue-500/10 border-blue-500/20',
      text: 'text-blue-400',
    },
    warning: {
      bg: 'bg-yellow-500/10 border-yellow-500/20',
      text: 'text-yellow-400',
    },
  };
  return colors[type];
}

function getIcon(type: ToastType) {
  const icons = {
    success: 'check_circle',
    error: 'error',
    info: 'info',
    warning: 'warning',
  };
  return icons[type];
}

// Inject CSS animations globally
if (!document.getElementById('toast-styles')) {
  const style = document.createElement('style');
  style.id = 'toast-styles';
  style.textContent = `
    @keyframes slide-in {
      from {
        transform: translateX(400px);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
    @keyframes slide-out {
      from {
        transform: translateX(0);
        opacity: 1;
      }
      to {
        transform: translateX(400px);
        opacity: 0;
      }
    }
    .animate-slide-in {
      animation: slide-in 300ms ease-out;
    }
  `;
  document.head.appendChild(style);
}

export default { toast };
