import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, User } from 'lucide-react';
import { authAPI } from '../services/api';

const Login = () => {
    const navigate = useNavigate();
    const [isLogin, setIsLogin] = useState(true);
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        email: '',
        password2: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            if (isLogin) {
                const response = await authAPI.login({
                    username: formData.username,
                    password: formData.password
                });
                localStorage.setItem('token', response.data.token);
                localStorage.setItem('user', JSON.stringify(response.data.user));
                navigate('/');
            } else {
                if (formData.password !== formData.password2) {
                    setError('Passwords do not match');
                    setLoading(false);
                    return;
                }
                const response = await authAPI.register(formData);
                localStorage.setItem('token', response.data.token);
                localStorage.setItem('user', JSON.stringify(response.data.user));
                navigate('/');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'An error occurred');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-[#39c5bb] via-[#22d3ee] to-[#ec4899] flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-white rounded-3xl shadow-2xl overflow-hidden">
                {/* Header */}
                <div className="miku-animated-bg p-8 text-white">
                    <div className="flex justify-center mb-4">
                        <img src="/miku.svg" alt="Miku" className="w-20 h-20 rounded-full ring-4 ring-white/60 object-cover bg-white/25 miku-float" />
                    </div>
                    <h1 className="text-3xl font-bold text-center font-miku">Miku Beam Sentinel</h1>
                    <p className="text-center text-white/90 mt-2">API Security Scanner ✨</p>
                </div>

                {/* Form */}
                <div className="p-8">
                    <div className="flex gap-4 mb-6">
                        <button
                            onClick={() => setIsLogin(true)}
                            className={`flex-1 py-2 rounded-lg font-semibold transition-colors ${isLogin ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-600'
                                }`}
                        >
                            Login
                        </button>
                        <button
                            onClick={() => setIsLogin(false)}
                            className={`flex-1 py-2 rounded-lg font-semibold transition-colors ${!isLogin ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-600'
                                }`}
                        >
                            Register
                        </button>
                    </div>

                    {error && (
                        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                            {error}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="block text-gray-700 font-medium mb-2">
                                <User className="inline w-4 h-4 mr-2" />
                                Username
                            </label>
                            <input
                                type="text"
                                name="username"
                                value={formData.username}
                                onChange={handleChange}
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-400 focus:border-transparent"
                                required
                            />
                        </div>

                        {!isLogin && (
                            <div>
                                <label className="block text-gray-700 font-medium mb-2">
                                    <Mail className="inline w-4 h-4 mr-2" />
                                    Email
                                </label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-400 focus:border-transparent"
                                    required={!isLogin}
                                />
                            </div>
                        )}

                        <div>
                            <label className="block text-gray-700 font-medium mb-2">
                                <Lock className="inline w-4 h-4 mr-2" />
                                Password
                            </label>
                            <input
                                type="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-400 focus:border-transparent"
                                required
                            />
                        </div>

                        {!isLogin && (
                            <div>
                                <label className="block text-gray-700 font-medium mb-2">
                                    <Lock className="inline w-4 h-4 mr-2" />
                                    Confirm Password
                                </label>
                                <input
                                    type="password"
                                    name="password2"
                                    value={formData.password2}
                                    onChange={handleChange}
                                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-400 focus:border-transparent"
                                    required={!isLogin}
                                />
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-pink-500 to-cyan-500 text-white py-3 rounded-xl font-semibold hover:from-pink-600 hover:to-cyan-600 transition-all disabled:opacity-50 shadow-md"
                        >
                            {loading ? 'Please wait...' : isLogin ? 'Login' : 'Register'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default Login;
