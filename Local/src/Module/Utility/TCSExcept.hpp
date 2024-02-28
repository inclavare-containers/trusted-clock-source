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
    private:
        std::string m_statement;

        void fillErrorStatement(const std::string &_msg, const std::string &_var = "")
        {
            m_statement = std::string("Uninitialized: ") + _msg + " | Variable: " + _var;
        }

    public:
        UnInitializedException(const std::string &_msg) : TCSExcept()
        {
            fillErrorStatement(_msg);
        }

        UnInitializedException(const std::string &_msg, const std::string &_var) : TCSExcept()
        {
            fillErrorStatement(_msg, _var);
        }

        virtual const char *what() const noexcept override
        {
            return m_statement.c_str();
        }
    };

    class InvalidArgumentException : public TCSExcept
    {
    private:
        std::string m_statement;

        void fillErrorStatement(const std::string &_msg, const std::string &_arg = "")
        {
            m_statement = std::string("Invalid Argument: ") + _msg + " | Argument: " + _arg;
        }

    public:
        InvalidArgumentException(const std::string &_msg) : TCSExcept()
        {
            fillErrorStatement(_msg);
        }
        InvalidArgumentException(const std::string &_msg, const std::string &_arg) : TCSExcept()
        {
            fillErrorStatement(_msg, _arg);
        }

        virtual const char *what() const noexcept override
        {
            return m_statement.c_str();
        }
    };

}

#endif