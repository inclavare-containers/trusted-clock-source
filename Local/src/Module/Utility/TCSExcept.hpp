/***
 *
 *
 *
 */

#ifndef TCSEXCEPT_H_
#define TCSEXCEPT_H_

#include <stdexcept>

namespace TCS
{
    class TCSExcept : public std::exception
    {
    public:
        std::string m_Msg;

    public:
        TCSExcept() = default;
        TCSExcept(const char *_msg) : m_Msg(_msg) {}
        TCSExcept(const std::string &_msg) : m_Msg(_msg) {}

        virtual const char *what() const noexcept override
        {
            return m_Msg.c_str();
        }
    };

    class UnInitializedException : public TCSExcept
    {
    public:
        UnInitializedException(const char *_msg) : TCSExcept(_msg) {}

        UnInitializedException(const std::string &_msg) : TCSExcept(_msg) {}
        UnInitializedException(const std::string &_msg, const std::string &_var)
        {
            TCSExcept(std::string("Uninitialized: ") + m_Msg + " | Variable: " + _var);
        }
    };

    class InvalidArgumentException : public TCSExcept
    {
    private:
        std::string m_ArgName;

    public:
        InvalidArgumentException(const char *_msg) : TCSExcept(_msg), m_ArgName("") {}
        InvalidArgumentException(const std::string &_msg) : TCSExcept(_msg), m_ArgName("") {}
        InvalidArgumentException(const std::string &_msg, const std::string &_arg) : TCSExcept(_msg), m_ArgName(_arg) {}
    };

}

#endif