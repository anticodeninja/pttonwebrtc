// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace PttOnWebRtc
{
    class Resources
    {
        public static IEnumerable<string> Enumerate(string path)
        {
            foreach (var item in Assembly.GetExecutingAssembly().GetManifestResourceNames())
            {
                if (!item.StartsWith(path)) continue;
                yield return item;
            }
        }

        public static byte[] ReadFile(string path)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(path))
            {
                var buffer = new byte[stream.Length];
                stream.Read(buffer, 0, buffer.Length);
                return buffer;
            }
        }
    }
}