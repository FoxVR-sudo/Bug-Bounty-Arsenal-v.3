import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiCheckCircle, FiArrowRight } from 'react-icons/fi';

const PaymentSuccess = () => {
  const [countdown, setCountdown] = useState(5);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          navigate('/verify-phone');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl text-center">
          <div className="mb-6">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-green-100 rounded-full">
              <FiCheckCircle className="text-green-600" size={48} />
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-4 text-gray-900 dark:text-white">Payment Successful!</h1>
          <p className="text-gray-600 dark:text-gray-300 mb-6">Thank you for your purchase. Your subscription has been activated successfully.</p>
          <div className="bg-gray-50 dark:bg-gray-950/30 border border-gray-200 dark:border-gray-700 rounded-lg p-6 mb-6">
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">Redirecting to phone verification in</p>
            <div className="text-4xl font-bold text-primary mb-2">{countdown}</div>
            <p className="text-xs text-gray-500 dark:text-gray-400">seconds</p>
          </div>
          <button onClick={() => navigate('/verify-phone')} className="ui-btn ui-btn-primary w-full justify-center gap-2">
            Continue Now <FiArrowRight />
          </button>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-4">You can view your subscription details in your dashboard</p>
        </div>
      </div>
    </div>
  );
};

export default PaymentSuccess;
