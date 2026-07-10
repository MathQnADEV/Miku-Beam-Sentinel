import React from 'react';

const Input = ({ label, type = 'text', value, onChange, placeholder = '', className = '' }) => {
    return (
        <div className={`flex flex-col gap-1 ${className}`}>
            {label && <label className="text-sm font-semibold text-gray-700">{label}</label>}
            <input
                type={type}
                value={value}
                onChange={onChange}
                placeholder={placeholder}
                className="px-4 py-2 border border-pink-200 rounded-xl bg-white/70 focus:outline-none focus:ring-2 focus:ring-pink-300 focus:border-pink-400 transition"
            />
        </div>
    );
};

export default Input;
