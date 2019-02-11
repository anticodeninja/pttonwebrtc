// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System;

    internal class Program
    {
        public static void Main(string[] args)
        {
            using (var server = new Server())
            {
                server.Start();
                Console.WriteLine("PttOnWebRtc runned");
                Console.ReadLine();
            }
        }
    }
}