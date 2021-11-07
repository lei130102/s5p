#ifndef ENCODE_H
#define ENCODE_H

#include <algorithm>
#include <iterator>

template<typename TInIterator, typename TOutIterator>
void encode(TInIterator begin, TInIterator end, TOutIterator out)
{
    while(begin != end)
    {
        *out++ = *begin++ ^ 108;
    }
}

template<typename TInIterator, typename TOutIterator>
void decode(TInIterator begin, TInIterator end, TOutIterator out)
{
    while(begin != end)
    {
        *out++ = *begin++ ^ 108;
    }
}

#endif // ENCODE_H
