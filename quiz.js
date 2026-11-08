/**
 * Phishing Detection Platform - Educational Awareness & Spot-the-Phish Quiz
 */

const quizQuestions = [
  {
    id: 1,
    url: 'https://accounts.google.com/signin/v2/identifier',
    legitimate: true,
    target: 'Google Account',
    explanation: 'সঠিক ডোমেইন accounts.google.com হলো গুগলের অফিশিয়াল সাবডোমেন। এতে ভ্যালিড গুগল ট্রাস্ট সার্ভিসেস SSL এনক্রিপশন রয়েছে।'
  },
  {
    id: 2,
    url: 'http://paypal-security-update.account-verify.xyz/login',
    legitimate: false,
    target: 'PayPal',
    explanation: 'ফিশিং! এখানে আসল ডোমেইন হলো account-verify.xyz (উচ্চ ঝুঁকিপূর্ণ TLD)। সাবডোমেনে paypal-security-update বসিয়ে আসল ব্র্যান্ড নকল করা হয়েছে।'
  },
  {
    id: 3,
    url: 'http://192.168.1.55/chase-online/index.html',
    legitimate: false,
    target: 'Chase Bank',
    explanation: 'ফিশিং! কোনো আসল ব্যাংক কখনোই ডোমেনের বদলে সরাসরি IP অ্যাড্রেস ব্যবহার করে কাস্টমারদের লগইন করায় না।'
  },
  {
    id: 4,
    url: 'https://www.github.com/torvalds/linux',
    legitimate: true,
    target: 'GitHub',
    explanation: 'সঠিক! এটি অফিসিয়াল GitHub রিপোজিটরি, সঠিক ডোমেন ও এক্সটেন্ডেড ভ্যালিডেশন SSL সহ।'
  },
  {
    id: 5,
    url: 'http://appleid.apple.com@evil-attacker.ru/verify',
    legitimate: false,
    target: 'Apple ID',
    explanation: 'ফিশিং! URL-এ "@" চিহ্ন ব্যবহারের মাধ্যমে ব্রাউজার evil-attacker.ru সাইটে কানেক্ট করবে। বাম পাশের পুরো appleid.apple.com অংশটি বাতিল হয়ে যাবে।'
  }
];

let currentQuestionIndex = 0;
let userQuizScore = 0;

function renderQuizQuestion() {
  const container = document.getElementById('quizContainer');
  if (!container) return;

  if (currentQuestionIndex >= quizQuestions.length) {
    container.innerHTML = `
      <div class="glass-panel p-8 rounded-2xl text-center">
        <div class="w-16 h-16 mx-auto rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-3xl mb-4">
          <i class="fa-solid fa-award"></i>
        </div>
        <h3 class="text-2xl font-bold text-white mb-2">কুইজ সম্পন্ন হয়েছে!</h3>
        <p class="text-slate-300 text-sm mb-4">
          আপনার অর্জিত স্কোর: <strong class="text-cyan-400 text-xl font-mono">${userQuizScore} / ${quizQuestions.length}</strong>
        </p>
        <p class="text-xs text-slate-400 mb-6 max-w-md mx-auto">
          ${userQuizScore >= 4 ? 'অসাধারণ! আপনার ফিশিং ও সাইবার থ্রেট সচেতনতা অত্যন্ত প্রশংসনীয়।' : 'নিয়মিত আমাদের প্ল্যাটফর্মের এনালাইসিস টুল ব্যবহার করে ফিশিং টেকনিকগুলো আরও ভালোভাবে চিনে নিন।'}
        </p>
        <button onclick="resetQuiz()" class="px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-xl font-bold text-sm text-white shadow-lg shadow-cyan-500/20 transition-all">
          আবার খেলুন
        </button>
      </div>
    `;
    return;
  }

  const q = quizQuestions[currentQuestionIndex];
  container.innerHTML = `
    <div class="glass-panel p-6 rounded-2xl">
      <div class="flex items-center justify-between text-xs text-slate-400 mb-4 pb-2 border-b border-slate-800">
        <span>প্রশ্ন ${currentQuestionIndex + 1} / ${quizQuestions.length}</span>
        <span>টার্গেট ব্র্যান্ড: <strong class="text-slate-200">${q.target}</strong></span>
      </div>

      <div class="text-sm font-semibold text-slate-200 mb-2">
        নিচের URL টি কি আসল (Legitimate) নাকি ফিশিং সাইট?
      </div>

      <div class="p-3 bg-slate-900 border border-slate-700/60 rounded-xl font-mono text-cyan-400 text-sm break-all mb-6 select-all">
        ${q.url}
      </div>

      <div id="quizActionButtons" class="grid grid-cols-2 gap-4 mb-4">
        <button onclick="handleQuizAnswer(true)" class="py-3 px-4 bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-500/40 rounded-xl text-emerald-400 font-bold text-sm flex items-center justify-center gap-2 transition-all">
          <i class="fa-solid fa-circle-check"></i> বৈধ ও নিরাপদ
        </button>
        <button onclick="handleQuizAnswer(false)" class="py-3 px-4 bg-red-950/40 hover:bg-red-900/60 border border-red-500/40 rounded-xl text-red-400 font-bold text-sm flex items-center justify-center gap-2 transition-all">
          <i class="fa-solid fa-triangle-exclamation"></i> ভুয়া / ফিশিং
        </button>
      </div>

      <div id="quizFeedbackBox" class="hidden"></div>
    </div>
  `;
}

function handleQuizAnswer(userSaysLegit) {
  const q = quizQuestions[currentQuestionIndex];
  const isCorrect = userSaysLegit === q.legitimate;
  if (isCorrect) userQuizScore++;

  const btns = document.getElementById('quizActionButtons');
  if (btns) btns.classList.add('hidden');

  const feedback = document.getElementById('quizFeedbackBox');
  if (feedback) {
    feedback.classList.remove('hidden');
    feedback.innerHTML = `
      <div class="p-4 rounded-xl border ${isCorrect ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' : 'bg-red-950/30 border-red-500/40 text-red-300'} text-xs">
        <div class="font-bold text-sm flex items-center gap-2 mb-1">
          <i class="fa-solid ${isCorrect ? 'fa-circle-check text-emerald-400' : 'fa-circle-xmark text-red-400'}"></i>
          ${isCorrect ? 'সঠিক উত্তর!' : 'ভুল উত্তর!'}
        </div>
        <p class="text-slate-200 mt-1">${q.explanation}</p>
        <button onclick="nextQuizQuestion()" class="mt-4 px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold">
          পরবর্তী প্রশ্ন <i class="fa-solid fa-arrow-right ml-1"></i>
        </button>
      </div>
    `;
  }
}

function nextQuizQuestion() {
  currentQuestionIndex++;
  renderQuizQuestion();
}

function resetQuiz() {
  currentQuestionIndex = 0;
  userQuizScore = 0;
  renderQuizQuestion();
}

// Init quiz on load
window.addEventListener('DOMContentLoaded', () => {
  renderQuizQuestion();
});
