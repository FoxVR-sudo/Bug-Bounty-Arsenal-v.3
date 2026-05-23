import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import api from '../services/api';

const VerifyEmail = () => {
  const { uid, token } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState('verifying'); // 'verifying', 'success', 'error'
  const [message, setMessage] = useState('Verifying your email...');

  const redirectTimerRef = useRef(null);

  useEffect(() => {
    const verifyEmail = async () => {
      try {
        const response = await api.post('/auth/verify-email/', {
          uid: uid,
          token: token,
        });

        setStatus('success');
        setMessage(response.data.message || 'Email verified successfully!');
        
        // Redirect to login after 3 seconds
        redirectTimerRef.current = setTimeout(() => {
          navigate('/login');
        }, 3000);

      } catch (error) {
        setStatus('error');
        setMessage(
          error.response?.data?.error || 
          'Verification failed. The link may be expired or invalid.'
        );
      }
    };

    if (uid && token) {
      verifyEmail();
    } else {
      setStatus('error');
      setMessage('Invalid verification link.');
    }
    return () => {
      if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
    };
  }, [uid, token, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-purple-800 to-indigo-900">
      <div className="max-w-md w-full mx-4">
        <div className="ui-card p-8 bg-white/90 dark:bg-gray-900/60 backdrop-blur-xl">
          <div className="text-center">
            {status === 'verifying' && (
              <LoadingState title="Verifying email" subtitle={message} />
            )}

            {status === 'success' && (
              <>
                <div className="bg-green-100 rounded-full h-16 w-16 flex items-center justify-center mx-auto mb-4">
                  <svg className="h-10 w-10 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-2">Email Verified!</h2>
                <p className="text-gray-600 dark:text-gray-300 mb-4">{message}</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">Redirecting to login page...</p>
              </>
            )}

            {status === 'error' && (
              <ErrorState
                title="Verification failed"
                subtitle={message}
                action={
                  <button onClick={() => navigate('/login')} className="ui-btn ui-btn-primary">
                    Go to Login
                  </button>
                }
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail;
