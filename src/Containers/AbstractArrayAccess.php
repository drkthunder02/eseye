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

namespace Seat\Eseye\Containers;

/**
 * Class AbstractArrayAccess.
 *
 * @package Seat\Eseye\Containers
 */
abstract class AbstractArrayAccess implements \ArrayAccess
{

    /**
     * @var
     */
    protected $data;

    /**
     * @param  mixed  $offset
     * @return bool
     */
    public function offsetExists(mixed $offset): mixed
    {

        return array_key_exists($offset, $this->data);
    }

    /**
     * @param  mixed  $offset
     * @return mixed
     */
    public function offsetGet(mixed $offset): mixed
    {

        return $this->data[$offset];
    }

    /**
     * @param  mixed  $offset
     * @param  mixed  $value
     */
    public function offsetSet(mixed $offset, mixed $value): mixed
    {

        $this->data[$offset] = $value;
    }

    /**
     * @param  mixed  $offset
     */
    public function offsetUnset(mixed $offset): mixed
    {

        unset($this->data[$offset]);
    }

    /**
     * @param $key
     * @return mixed
     */
    public function __get(string $key): mixed
    {
        return $this[$key];
    }

    /**
     * @param string $key
     * @param mixed $val
     */
    public function __set(string $key, mixed $val): void
    {
        $this[$key] = $val;
    }
}
