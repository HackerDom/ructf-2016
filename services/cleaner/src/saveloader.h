#pragma once

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

namespace NSaveloader {
    template <typename T>
    bool Save(const T& obj, const boost::filesystem::path& file) {
        using boost::filesystem::exists;
        using boost::filesystem::ofstream;

        if (exists(file)) {
            return false;
        }

        ofstream ofs(file);
        boost::archive::text_oarchive oa(ofs);
        oa << obj;

        return true;
    }

    template <typename T>
    bool Load(T& obj, const boost::filesystem::path& file) {
        using boost::filesystem::path;
        using boost::filesystem::exists;
        using boost::filesystem::ifstream;

        if (!exists(file)) {
            return false;
        }

        ifstream ifs(file);
        boost::archive::text_iarchive ia(ifs);
        ia >> obj;

        return true;
    }
}
