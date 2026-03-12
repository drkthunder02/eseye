<?php

/*
 * This file is part of SeAT
 *
 * Copyright (C) 2015 to 2022 Leon Jacobs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

if (! function_exists('carbon')) {

    /**
     * A helper to get a fresh instance of Carbon.
     *
     * @param  null  $data
     * @param \DateTimeInterface|int|float|string|null $date
     * @return \Carbon\Carbon
     */
    function carbon(\DateTimeInterface|int|float|string|null $data = null): \Carbon\Carbon
    {
        if ($data instanceof \DateTimerInterface)
            return \Carbon\Carbon::instance($data);
        if(is_int($data) || is_float($data) || (is_string($data) && is_numeric($data)))
                return \Carbon\Carbon::createFromTimestampUTC($data);
            
        if (! is_null($data))
            return new \Carbon\Carbon($data);

        return new \Carbon\Carbon;
    }
}
