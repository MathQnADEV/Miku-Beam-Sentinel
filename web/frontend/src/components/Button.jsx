import React from 'react';

const Button = ({ children, onClick, type = 'button', className = '', disabled = false }) => {
    return (
        <button
            type={type}
            onClick={onClick}
            disabled={disabled}
            className={`px-5 py-2 bg-gradient-to-r from-pink-500 to-cyan-500 text-white rounded-xl font-semibold shadow-md hover:shadow-lg hover:from-pink-600 hover:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all ${className}`}
        >
            {children}
        </button>
    );
};

export default Button;
